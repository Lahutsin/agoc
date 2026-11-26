use super::*;
#[cfg(target_os = "macos")]
use tao::platform::macos::{ActivationPolicy, EventLoopExtMacOS};
use tao::{
    event::{Event as TaoEvent, StartCause},
    event_loop::{ControlFlow, EventLoopBuilder, EventLoopWindowTarget},
};
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    Icon, TrayIconBuilder,
};

/// The macOS menu bar draws status icons 18 pt high (tray-icon sets the NSImage
/// size to 18 pt). 36 px is pixel-exact on Retina (@2x) and a clean 2:1
/// downscale on @1x displays, so the icon is never blurred by fractional scaling.
#[cfg(target_os = "macos")]
fn icon_size(_: &EventLoopWindowTarget<Event>) -> u32 {
    36
}

/// The Windows notification area shows small icons: 16 px at 100 % scaling,
/// 20 px at 125 %, 24 px at 150 %, 32 px at 200 % and so on.
#[cfg(windows)]
fn icon_size(target: &EventLoopWindowTarget<Event>) -> u32 {
    windows_icon_size(
        target
            .primary_monitor()
            .map_or(1.0, |monitor| monitor.scale_factor()),
    )
}

pub(super) fn run(options: Options) -> Result<()> {
    let all_artwork = artwork()?;
    let mut artwork = None;
    #[cfg(target_os = "macos")]
    let mut event_loop = EventLoopBuilder::<Event>::with_user_event().build();
    #[cfg(not(target_os = "macos"))]
    let event_loop = EventLoopBuilder::<Event>::with_user_event().build();
    #[cfg(target_os = "macos")]
    event_loop.set_activation_policy(ActivationPolicy::Accessory);
    let proxy = event_loop.create_proxy();
    MenuEvent::set_event_handler(Some(move |_| {
        if let Err(error) = proxy.send_event(Event::Quit) {
            eprintln!("Cannot request quit: {error:?}");
        }
    }));
    let proxy = event_loop.create_proxy();
    ctrlc::set_handler(move || {
        if let Err(error) = proxy.send_event(Event::Quit) {
            eprintln!("Cannot request quit: {error:?}");
        }
    })?;
    let mut view = View::default();
    let menu = Menu::new();
    let status = MenuItem::new(&view.label, false, None);
    let details = view
        .details
        .each_ref()
        .map(|label| MenuItem::new(label, false, None));
    let quit = MenuItem::new("Quit (remove protection)", true, None);
    menu.append_items(&[
        &status,
        &details[0],
        &details[1],
        &details[2],
        &PredefinedMenuItem::separator(),
        &quit,
    ])?;
    let mut icon = None;
    let mut worker = None;
    let mut options = Some(options);
    let proxy = event_loop.create_proxy();
    event_loop.run(move |event, target, flow| {
        *flow = ControlFlow::Wait;
        let result = (|| -> Result<bool> {
            match event {
                TaoEvent::NewEvents(StartCause::Init) => {
                    let size = icon_size(target);
                    let art = all_artwork
                        .iter()
                        .find(|art| art.size == size)
                        .with_context(|| format!("Missing {size}px tray icon"))?
                        .clone();
                    icon = Some(
                        TrayIconBuilder::new()
                            .with_menu(Box::new(menu.clone()))
                            .with_tooltip("AGOC")
                            .with_icon(Icon::from_rgba(pixels(&art, view.color), size, size)?)
                            .build()?,
                    );
                    artwork = Some(art);
                    let worker_proxy = proxy.clone();
                    worker = Some(Worker::start(
                        options.take().context("Tray already started")?,
                        move |event| {
                            if let Err(error) = worker_proxy.send_event(event) {
                                eprintln!("Tray closed before receiving monitor event: {error:?}");
                            }
                        },
                    )?);
                    proxy.send_event(Event::Refresh).map_err(|error| {
                        anyhow::anyhow!("Cannot wake tray event loop: {error:?}")
                    })?;
                }
                TaoEvent::UserEvent(event) => {
                    if let Some(worker) = &worker {
                        if view.event(event, worker)? {
                            return Ok(true);
                        }
                    }
                    status.set_text(&view.label);
                    for (item, text) in details.iter().zip(&view.details) {
                        item.set_text(text);
                    }
                    quit.set_enabled(!view.quitting);
                    if let (Some(icon), Some(art)) = (&icon, &artwork) {
                        icon.set_icon(Some(Icon::from_rgba(
                            pixels(art, view.color),
                            art.size,
                            art.size,
                        )?))?;
                        icon.set_tooltip(Some(&view.label))?;
                    }
                }
                _ => {}
            }
            Ok(false)
        })();
        match result {
            Ok(true) => {
                icon.take();
                *flow = ControlFlow::Exit;
            }
            Err(error) => {
                eprintln!("Tray error: {error:#}");
                status.set_text(fit(&format!("Error: {}", reason(&format!("{error:#}")))));
                if worker.is_none() {
                    icon.take();
                    *flow = ControlFlow::Exit;
                }
            }
            Ok(false) => {}
        }
    })
}
