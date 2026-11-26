//! Thin wrappers over the Win32 APIs AGOC needs on Windows: token elevation,
//! trusted system paths, an administrator-only data directory, network tables
//! (adapters, default routes, unicast addresses) and the UAC-elevated helper.

use crate::network::{WinAdapter, WinAddress, WinRoute};
use anyhow::{bail, Context, Result};
use std::{
    collections::HashMap,
    ffi::OsString,
    fs::OpenOptions,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::IntoRawHandle,
    },
    path::{Path, PathBuf},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, LocalFree, ERROR_ALREADY_EXISTS, ERROR_CANCELLED, HANDLE, HLOCAL, NO_ERROR,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    NetworkManagement::IpHelper::{
        FreeMibTable, GetIfTable2, GetIpForwardTable2, GetIpInterfaceTable,
        GetUnicastIpAddressTable, MIB_IF_TABLE2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_TABLE,
        MIB_UNICASTIPADDRESS_TABLE,
    },
    NetworkManagement::Ndis::IfOperStatusUp,
    Networking::WinSock::{IpDadStatePreferred, AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_INET},
    Security::{
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
            SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
        },
        Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG},
        GetSecurityDescriptorDacl, GetTokenInformation, IsWellKnownSid, TokenElevation,
        WinBuiltinAdministratorsSid, WinLocalSystemSid, ACL, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        PSID, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY,
    },
    Storage::FileSystem::{
        CreateDirectoryW, GetFileAttributesW, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, INVALID_FILE_ATTRIBUTES,
    },
    System::{
        Com::{CoInitializeEx, CoTaskMemFree, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE},
        Console::{GetStdHandle, SetStdHandle, STD_ERROR_HANDLE},
        SystemInformation::{GetSystemDirectoryW, GetSystemWindowsDirectoryW},
        Threading::{
            GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, TerminateProcess,
            WaitForSingleObject,
        },
    },
    UI::{
        Shell::{
            FOLDERID_LocalAppData, FOLDERID_ProgramData, SHGetKnownFolderPath, ShellExecuteExW,
            SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
        },
        WindowsAndMessaging::SW_HIDE,
    },
};

/// Administrator-only data directory: SYSTEM and Administrators have full
/// control, Users may only read (the log contains no secrets). Protected, so
/// nothing is inherited from `C:\ProgramData`, which users may write to.
const DATA_DIRECTORY_SDDL: &str =
    "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

/// Logs larger than this are truncated when a new monitor starts.
const LOG_LIMIT: u64 = 1024 * 1024;

fn wide(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

fn from_wide(value: &[u16]) -> String {
    let end = value.iter().position(|&c| c == 0).unwrap_or(value.len());
    String::from_utf16_lossy(&value[..end])
}

/// Whether this process runs with an elevated (administrator) token.
pub fn is_elevated() -> Result<bool> {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(std::io::Error::last_os_error()).context("OpenProcessToken failed");
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut length = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut length,
        );
        let error = std::io::Error::last_os_error();
        CloseHandle(token);
        if ok == 0 {
            return Err(error).context("GetTokenInformation(TokenElevation) failed");
        }
        Ok(elevation.TokenIsElevated != 0)
    }
}

fn system_path(getter: unsafe extern "system" fn(*mut u16, u32) -> u32) -> Result<PathBuf> {
    let mut buffer = vec![0u16; 512];
    let length = unsafe { getter(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(std::io::Error::last_os_error())
            .context("Cannot resolve the Windows directory");
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..length])))
}

/// `C:\Windows\System32`, from the API rather than from (user-controlled)
/// environment variables, because the elevated helper starts system tools.
pub fn system_directory() -> Result<PathBuf> {
    system_path(GetSystemDirectoryW)
}

/// `C:\Windows`, from the API rather than from `%SystemRoot%`/`%windir%`.
pub fn windows_directory() -> Result<PathBuf> {
    system_path(GetSystemWindowsDirectoryW)
}

fn known_folder(id: &windows_sys::core::GUID) -> Result<PathBuf> {
    unsafe {
        let mut path = null_mut();
        let result = SHGetKnownFolderPath(id, 0, null_mut(), &mut path);
        if result < 0 || path.is_null() {
            CoTaskMemFree(path as *const _);
            bail!("SHGetKnownFolderPath failed: HRESULT {result:#x}");
        }
        let length = (0..).take_while(|&i| *path.add(i) != 0).count();
        let value = OsString::from_wide(std::slice::from_raw_parts(path, length));
        CoTaskMemFree(path as *const _);
        Ok(PathBuf::from(value))
    }
}

/// Per-user application data (`%LOCALAPPDATA%\agoc`), for the unprivileged tray.
pub fn user_data_directory() -> Result<PathBuf> {
    let path = known_folder(&FOLDERID_LocalAppData)?.join("agoc");
    std::fs::create_dir_all(&path).with_context(|| format!("Cannot create {}", path.display()))?;
    Ok(path)
}

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self> {
        let mut descriptor = null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(sddl).as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error()).context("Invalid security descriptor");
        }
        Ok(Self(descriptor))
    }

    fn dacl(&self) -> Result<*mut ACL> {
        let (mut present, mut defaulted, mut dacl) = (0, 0, null_mut());
        if unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted) }
            == 0
            || present == 0
        {
            bail!("Security descriptor has no DACL");
        }
        Ok(dacl)
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0 as HLOCAL) };
    }
}

fn attributes(path: &Path) -> Result<u32> {
    let value = unsafe { GetFileAttributesW(wide(path).as_ptr()) };
    if value == INVALID_FILE_ATTRIBUTES {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("Cannot read attributes of {}", path.display()));
    }
    Ok(value)
}

/// Whether `path` is owned by BUILTIN\Administrators or SYSTEM and is not a
/// reparse point (symlink/junction). A file or directory created by a standard
/// user is owned by that user.
pub fn owned_by_administrators(path: &Path) -> Result<bool> {
    if attributes(path)? & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Ok(false);
    }
    unsafe {
        let mut owner: PSID = null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        let result = GetNamedSecurityInfoW(
            wide(path).as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        );
        if result != NO_ERROR {
            bail!(
                "Cannot read the owner of {}: {}",
                path.display(),
                std::io::Error::from_raw_os_error(result as i32)
            );
        }
        let trusted = IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
            || IsWellKnownSid(owner, WinLocalSystemSid) != 0;
        LocalFree(descriptor as HLOCAL);
        Ok(trusted)
    }
}

/// `%ProgramData%\agoc`, created by the elevated helper with an
/// administrator-only DACL. An existing directory must already be owned by
/// Administrators/SYSTEM (a standard user could otherwise pre-create it and
/// plant links), and its DACL is reset on every start.
pub fn secure_data_directory() -> Result<PathBuf> {
    let path = known_folder(&FOLDERID_ProgramData)?.join("agoc");
    let descriptor = SecurityDescriptor::from_sddl(DATA_DIRECTORY_SDDL)?;
    let attributes_in = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let name = wide(&path);
    if unsafe { CreateDirectoryW(name.as_ptr(), &attributes_in) } == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
            return Err(error).with_context(|| format!("Cannot create {}", path.display()));
        }
    }
    if attributes(&path)? & FILE_ATTRIBUTE_DIRECTORY == 0 || !owned_by_administrators(&path)? {
        bail!(
            "{} must be a directory owned by Administrators or SYSTEM; remove it and retry",
            path.display()
        );
    }
    let result = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            descriptor.dacl()?,
            null(),
        )
    };
    if result != NO_ERROR {
        bail!(
            "Cannot restrict permissions of {}: {}",
            path.display(),
            std::io::Error::from_raw_os_error(result as i32)
        );
    }
    Ok(path)
}

/// Whether this process has a usable standard error (a console or a redirect).
pub fn has_stderr() -> bool {
    let handle = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
    !handle.is_null() && handle as isize != -1
}

/// Send this process's standard error (and that of children started later
/// with inherited stdio) to `path`. Used by the hidden elevated helper and the
/// windowless tray, which have no visible console.
pub fn redirect_stderr(path: &Path) -> Result<()> {
    let truncate = std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > LOG_LIMIT);
    let mut options = OpenOptions::new();
    options.create(true);
    if truncate {
        options.write(true).truncate(true);
    } else {
        options.append(true);
    }
    let file = options
        .open(path)
        .with_context(|| format!("Cannot open log {}", path.display()))?;
    let handle = file.into_raw_handle();
    if unsafe { SetStdHandle(STD_ERROR_HANDLE, handle as HANDLE) } == 0 {
        return Err(std::io::Error::last_os_error()).context("SetStdHandle failed");
    }
    Ok(())
}

/// 32 random bytes from the system CSPRNG, hex-encoded.
pub fn random_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    let status = unsafe {
        BCryptGenRandom(
            null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        bail!("BCryptGenRandom failed: NTSTATUS {status:#x}");
    }
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Reads a MIB table (`NumEntries` followed by rows) and frees it.
unsafe fn read_table<Table, Row, T>(
    table: *mut Table,
    entries: impl Fn(&Table) -> (u32, *const Row),
    mut convert: impl FnMut(&Row) -> Option<T>,
) -> Vec<T> {
    let (count, rows) = entries(&*table);
    let result = std::slice::from_raw_parts(rows, count as usize)
        .iter()
        .filter_map(&mut convert)
        .collect();
    FreeMibTable(table as *const _);
    result
}

fn check(result: u32, what: &str) -> Result<()> {
    if result != NO_ERROR {
        bail!(
            "{what} failed: {}",
            std::io::Error::from_raw_os_error(result as i32)
        );
    }
    Ok(())
}

unsafe fn ip(address: &SOCKADDR_INET) -> Option<IpAddr> {
    match address.si_family {
        AF_INET => Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
            address.Ipv4.sin_addr.S_un.S_addr,
        )))),
        AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(address.Ipv6.sin6_addr.u.Byte))),
        _ => None,
    }
}

/// Network adapters with the properties needed to recognize a physical exit.
pub fn adapters() -> Result<Vec<WinAdapter>> {
    unsafe {
        let mut table: *mut MIB_IF_TABLE2 = null_mut();
        check(GetIfTable2(&mut table), "GetIfTable2")?;
        Ok(read_table(
            table,
            |table| (table.NumEntries, table.Table.as_ptr()),
            |row| {
                let flags = row.InterfaceAndOperStatusFlags._bitfield;
                Some(WinAdapter {
                    index: row.InterfaceIndex,
                    alias: from_wide(&row.Alias),
                    kind: row.Type,
                    // Bit 0: HardwareInterface, bit 1: FilterInterface.
                    hardware: flags & 0b01 != 0,
                    filter: flags & 0b10 != 0,
                    up: row.OperStatus == IfOperStatusUp,
                })
            },
        ))
    }
}

/// Default routes (0.0.0.0/0, ::/0) with their effective metric: the route
/// metric plus the interface metric, as Windows itself compares them.
pub fn default_routes() -> Result<Vec<WinRoute>> {
    unsafe {
        let mut interfaces: *mut MIB_IPINTERFACE_TABLE = null_mut();
        check(
            GetIpInterfaceTable(AF_UNSPEC, &mut interfaces),
            "GetIpInterfaceTable",
        )?;
        let metrics: HashMap<(u32, u16), u32> = read_table(
            interfaces,
            |table| (table.NumEntries, table.Table.as_ptr()),
            |row| Some(((row.InterfaceIndex, row.Family), row.Metric)),
        )
        .into_iter()
        .collect();
        let mut routes: *mut MIB_IPFORWARD_TABLE2 = null_mut();
        check(
            GetIpForwardTable2(AF_UNSPEC, &mut routes),
            "GetIpForwardTable2",
        )?;
        Ok(read_table(
            routes,
            |table| (table.NumEntries, table.Table.as_ptr()),
            |row| {
                if row.DestinationPrefix.PrefixLength != 0 {
                    return None;
                }
                let family = row.DestinationPrefix.Prefix.si_family;
                let interface = metrics.get(&(row.InterfaceIndex, family)).copied()?;
                Some(WinRoute {
                    index: row.InterfaceIndex,
                    ipv6: family == AF_INET6,
                    metric: row.Metric.saturating_add(interface),
                })
            },
        ))
    }
}

/// Unicast addresses of all interfaces.
pub fn unicast_addresses() -> Result<Vec<WinAddress>> {
    unsafe {
        let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = null_mut();
        check(
            GetUnicastIpAddressTable(AF_UNSPEC, &mut table),
            "GetUnicastIpAddressTable",
        )?;
        Ok(read_table(
            table,
            |table| (table.NumEntries, table.Table.as_ptr()),
            |row| {
                Some(WinAddress {
                    index: row.InterfaceIndex,
                    ip: ip(&row.Address)?,
                    usable: row.DadState == IpDadStatePreferred && !row.SkipAsSource,
                })
            },
        ))
    }
}

/// The administrator helper started through the UAC consent prompt.
pub struct ElevatedProcess {
    handle: HANDLE,
}

impl ElevatedProcess {
    /// Starts `program` elevated, with a hidden console. Blocks until the UAC
    /// prompt is answered. `parameters` must already be quoted for Windows.
    pub fn start(program: &Path, parameters: &str) -> Result<Self> {
        unsafe {
            // ShellExecuteEx may use COM-based shell extensions.
            let _ = CoInitializeEx(
                null(),
                (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
            );
            let verb = wide("runas");
            let file = wide(program);
            let parameters = wide(parameters);
            let directory = program.parent().map(wide);
            let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
            info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
            info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
            info.lpVerb = verb.as_ptr();
            info.lpFile = file.as_ptr();
            info.lpParameters = parameters.as_ptr();
            info.lpDirectory = directory.as_ref().map_or(null(), |value| value.as_ptr());
            info.nShow = SW_HIDE;
            if ShellExecuteExW(&mut info) == 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(ERROR_CANCELLED as i32) {
                    bail!("Administrator authorization was cancelled");
                }
                return Err(error).context("Cannot start the elevated helper");
            }
            if info.hProcess.is_null() {
                bail!("The elevated helper started without a process handle");
            }
            Ok(Self {
                handle: info.hProcess,
            })
        }
    }

    /// The exit code, once the process has exited.
    pub fn try_wait(&mut self) -> Result<Option<u32>> {
        unsafe {
            match WaitForSingleObject(self.handle, 0) {
                WAIT_OBJECT_0 => {
                    let mut code = 0;
                    if GetExitCodeProcess(self.handle, &mut code) == 0 {
                        return Err(std::io::Error::last_os_error())
                            .context("GetExitCodeProcess failed");
                    }
                    Ok(Some(code))
                }
                WAIT_TIMEOUT => Ok(None),
                _ => Err(std::io::Error::last_os_error()).context("WaitForSingleObject failed"),
            }
        }
    }

    /// Best effort: an unelevated caller may lack the right to terminate it.
    /// Without its control connection the helper stops on its own.
    pub fn terminate(&mut self) {
        unsafe { TerminateProcess(self.handle, 1) };
    }
}

impl Drop for ElevatedProcess {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle) };
    }
}
