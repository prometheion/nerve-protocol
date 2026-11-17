//! A guard for the Slint trap of ui/widgets.slint (Reveal): an `if` element
//! is measured at its unwrapped width, so text that wraps inside one runs out
//! of the box around it. Wrapping text that comes and goes sits in a Reveal.
//!
//! And the shared widgets of the pages' layout (#231), each page's list and
//! details: drawn without a screen in a page of their own, at the window's
//! sizes below and above the breakpoints.

use std::path::Path;

use nerve::headless::Screen;
use slint::ComponentHandle;

slint::slint! {
    import { PageFrame, Split, ListPane, DetailsPane, SidePane, ListCard, ListItem, ListSwitch, RemoveAsk } from "../ui/widgets.slint";
    import { Shape } from "../ui/theme.slint";
    export { Shape }

    component Probe inherits PageFrame {
        in property <bool> open;
        in property <int> rows;
        in-out property <int> made;
        in property <length> details-height: 200px;
        out property <length> details-shown-height: pane.tall;
        out property <length> list-x: list.absolute-position.x;
        out property <length> list-width: list.width;
        out property <length> card-height: card.height;
        out property <length> details-x: details.absolute-position.x;
        out property <length> details-y: details.absolute-position.y;
        out property <length> details-width: details.width;
        out property <bool> list-shown: list.visible;
        out property <bool> details-shown: pane.visible;
        out property <length> side-width: side.width;
        out property <length> split-width: split.width;
        out property <length> switch-height: switch.height;
        out property <length> top: root.view-top;
        in-out property <bool> asking;
        in-out property <int> removed;
        in-out property <int> stepped;
        public function focus-list() {
            card.focus();
        }
        out property <length> ask-x: remove.absolute-position.x + remove.width - 12px;
        out property <length> ask-y: remove.absolute-position.y + remove.height / 2;
        callback went-back();
        gap: 16px;
        HorizontalLayout {
            alignment: start;
            remove := RemoveAsk {
                label: "Remove row 3";
                asking: root.asking;
                ask => {
                    root.asking = true;
                }
                cancel => {
                    root.asking = false;
                }
                confirmed => {
                    root.asking = false;
                    root.removed += 1;
                }
            }
        }
        switch := ListSwitch {
            options: ["Folders", "Forbidden commands", "Allowed commands", "Sudo"];
            counts: ["4", "2", "3", "Off"];
        }
        split := Split {
            list := ListPane {
                open: root.open;
                card := ListCard {
                    step(d) => {
                        root.stepped += d;
                    }
                    for i in root.rows: ListItem {
                        first: i == 0;
                        selected: i == 3;
                        Text {
                            text: "row " + i;
                        }
                    }
                }
            }
            pane := DetailsPane {
                open: root.open;
                view-top: root.view-top;
                view-height: root.view-height;
                back => {
                    root.went-back();
                }
                details := Rectangle {
                    height: root.details-height;
                    background: blue;
                    init => {
                        root.made += 1;
                    }
                }
            }
            side := SidePane {
                Rectangle {
                    height: 50px;
                }
            }
        }
    }

    export component Window_ inherits Window {
        in property <bool> open <=> probe.open;
        in property <int> rows <=> probe.rows;
        out property <int> made: probe.made;
        in property <length> details-height <=> probe.details-height;
        out property <length> details-shown-height: probe.details-shown-height;
        out property <length> list-x: probe.list-x;
        out property <length> list-width: probe.list-width;
        out property <length> card-height: probe.card-height;
        out property <length> details-x: probe.details-x;
        out property <length> details-y: probe.details-y;
        out property <length> details-width: probe.details-width;
        out property <bool> list-shown: probe.list-shown;
        out property <bool> details-shown: probe.details-shown;
        out property <length> side-width: probe.side-width;
        out property <length> split-width: probe.split-width;
        out property <length> switch-height: probe.switch-height;
        out property <length> top: probe.top;
        callback went-back <=> probe.went-back;
        in-out property <bool> asking <=> probe.asking;
        out property <int> removed: probe.removed;
        out property <int> stepped: probe.stepped;
        public function focus-list() {
            probe.focus-list();
        }
        out property <length> ask-x: probe.ask-x;
        out property <length> ask-y: probe.ask-y;
        init => {
            Shape.window-width = self.width;
        }
        changed width => {
            Shape.window-width = self.width;
        }
        probe := Probe {
            width: 100%;
            height: 100%;
        }
    }
}

/// The `if` elements of `source` that hold wrapping text, as their lines.
fn wrapping_ifs(source: &str) -> Vec<usize> {
    let lines: Vec<&str> = source.lines().collect();
    let mut found = Vec::new();
    for (at, line) in lines.iter().enumerate() {
        let code = line.trim_start();
        if !(code.starts_with("if ") && code.contains(": ") && code.ends_with('{')) {
            continue;
        }
        // The element's body, up to its closing brace.
        let mut depth = 0i32;
        for body in &lines[at..] {
            depth += body.matches('{').count() as i32 - body.matches('}').count() as i32;
            if body.contains("wrap: word-wrap")
                || body.contains("wrap: char-wrap")
                || body.contains("TextWrap.")
            {
                found.push(at + 1);
                break;
            }
            if depth <= 0 {
                break;
            }
        }
    }
    found
}

#[test]
fn no_if_holds_wrapping_text() {
    let ui = Path::new(env!("CARGO_MANIFEST_DIR")).join("ui");
    let mut bad = Vec::new();
    for entry in std::fs::read_dir(&ui).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "slint") {
            let source = std::fs::read_to_string(&path).unwrap();
            for line in wrapping_ifs(&source) {
                bad.push(format!("{}:{line}", path.display()));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "wrapping text in an `if`, use Reveal: {bad:?}"
    );
}

/// The lines of `source`, outside comments, that send the owner to a
/// terminal (a command in backticks) or to the project's source tree.
fn terminal_hints(source: &str) -> Vec<usize> {
    source
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim_start().starts_with("//"))
        .filter(|(_, l)| l.contains('`') || l.contains("docs/user/ of"))
        .map(|(at, _)| at + 1)
        .collect()
}

#[test]
fn no_text_sends_the_owner_to_a_terminal() {
    let ui = Path::new(env!("CARGO_MANIFEST_DIR")).join("ui");
    let mut bad = Vec::new();
    for entry in std::fs::read_dir(&ui).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "slint") {
            let source = std::fs::read_to_string(&path).unwrap();
            for line in terminal_hints(&source) {
                bad.push(format!("{}:{line}", path.display()));
            }
        }
    }
    assert!(bad.is_empty(), "a text that points to a terminal: {bad:?}");
}

#[test]
fn finds_wrapping_text_in_an_if() {
    let source = "VerticalLayout {\n    if a: Text {\n        wrap: word-wrap;\n    }\n    if b: Button { }\n}\n";
    assert_eq!(wrapping_ifs(source), vec![2]);
}

/// The pages, each with one scroll for the whole page (#231): no list in a
/// box that scrolls on its own.
#[test]
fn no_page_scrolls_a_list_of_its_own() {
    let ui = Path::new(env!("CARGO_MANIFEST_DIR")).join("ui");
    for page in [
        "overview",
        "centers",
        "relay",
        "permissions",
        "capabilities",
        "audit",
        "log",
        "settings",
        "help",
        // The center role's (#232).
        "hub_login",
        "hub_overview",
        "hub_nodes",
        "hub_harnesses",
        "hub_checker",
        "hub_caps",
        "hub_watch",
        "hub_settings",
    ] {
        let source = std::fs::read_to_string(ui.join(format!("{page}.slint"))).unwrap();
        for scroller in ["ScrollBox", "ScrollView", "Flickable", "ListView"] {
            assert!(
                !source.contains(scroller),
                "{page}.slint scrolls in a {scroller} of its own"
            );
        }
    }
}

/// Draws the probe page `width` by `height` and lets its changes settle.
fn at(screen: &Screen, width: u32, height: u32) {
    screen.resize(width, height);
    for _ in 0..3 {
        screen.draw();
    }
}

/// The list and its details at the window's sizes (1440x900, 2200x1200,
/// 1024x700 and 900x580): side by side from 1100 px, in turns below it with Back to the list, the details in view while
/// the page scrolls a long list, a third pane from 1800 px, the page's cap,
/// the switch above a list wrapping where it is narrow, and one tree for
/// every size.
#[test]
fn the_list_and_its_details_follow_the_window() {
    let screen = Screen::install(1440, 900, 1.0).unwrap();
    let window = Window_::new().unwrap();
    window.set_rows(40);
    window.show().unwrap();
    at(&screen, 1440, 900);

    // Side by side: the list at the left, the details right of it, both
    // shown; the list grows with its rows, no scroll of its own.
    assert!(window.get_list_shown() && window.get_details_shown());
    assert!(
        window.get_details_x() > window.get_list_x() + window.get_list_width(),
        "the details are not right of the list"
    );
    assert!((260.0..=320.0).contains(&window.get_list_width()));
    assert_eq!(
        window.get_card_height(),
        40.0 * 40.0 + 6.0,
        "the list does not grow with its rows"
    );
    assert_eq!(window.get_side_width(), 0.0, "a third pane below 1800 px");

    // Scrolled far down the list, the details stay in view at its top.
    let top = window.get_top();
    window
        .window()
        .dispatch_event(slint::platform::WindowEvent::PointerScrolled {
            position: slint::LogicalPosition::new(100.0, 400.0),
            delta_x: 0.0,
            delta_y: -800.0,
        });
    screen.draw();
    let y = window.get_details_y();
    assert!(
        y >= top && y < top + 60.0,
        "the details scrolled away with the list: at {y}, the page's top at {top}"
    );

    // Details taller than the window keep within it, and scroll there.
    window.set_details_height(2000.0);
    screen.draw();
    assert!(
        window.get_details_shown_height() <= 900.0 - 32.0,
        "the details are {} high in a window of 900",
        window.get_details_shown_height()
    );
    window.set_details_height(200.0);
    screen.draw();

    // A large window adds the third pane; the page keeps margins past its
    // cap.
    at(&screen, 2200, 1200);
    // Its 380 px and the gap to the details.
    assert_eq!(window.get_side_width(), 396.0, "no third pane from 1800 px");
    assert!(
        window.get_split_width() > 1900.0 && window.get_split_width() <= 2000.0,
        "the page is {} wide in a window of 2200",
        window.get_split_width()
    );

    // Below 1100 px the list fills the page, without the details, until a
    // row opens them; then they take the list's place, and Back goes back.
    at(&screen, 1000, 700);
    assert!(window.get_list_shown() && !window.get_details_shown());
    assert!(
        window.get_list_width() > 900.0,
        "the list does not fill the page"
    );
    window.set_open(true);
    screen.draw();
    assert!(!window.get_list_shown() && window.get_details_shown());
    assert!(window.get_details_width() > 900.0);
    let back = std::rc::Rc::new(std::cell::Cell::new(false));
    let b = back.clone();
    window.on_went_back(move || b.set(true));
    for y in (0..300).step_by(4) {
        let position = slint::LogicalPosition::new(70.0, y as f32);
        let w = window.window();
        w.dispatch_event(slint::platform::WindowEvent::PointerPressed {
            position,
            button: slint::platform::PointerEventButton::Left,
        });
        w.dispatch_event(slint::platform::WindowEvent::PointerReleased {
            position,
            button: slint::platform::PointerEventButton::Left,
        });
        if back.get() {
            break;
        }
    }
    assert!(back.get(), "no Back to the list above the details");
    // The app's least window: the same.
    at(&screen, 900, 580);
    assert!(!window.get_list_shown() && window.get_details_shown());
    window.set_open(false);
    screen.draw();
    assert!(window.get_list_shown() && !window.get_details_shown());
    assert!(
        window.get_list_width() > 800.0,
        "the list does not fill the page"
    );

    // The switch above a list takes a second line where it is narrow.
    let one = window.get_switch_height();
    at(&screen, 420, 700);
    assert!(
        window.get_switch_height() > one * 1.5,
        "the switch does not wrap: {} high, {one} on one line",
        window.get_switch_height()
    );

    // A remove button asks in its place: the first click asks, Remove at
    // the same place removes; nothing is removed by the first.
    at(&screen, 1440, 900);
    let press = |x: f32, y: f32| {
        let position = slint::LogicalPosition::new(x, y);
        let w = window.window();
        w.dispatch_event(slint::platform::WindowEvent::PointerPressed {
            position,
            button: slint::platform::PointerEventButton::Left,
        });
        w.dispatch_event(slint::platform::WindowEvent::PointerReleased {
            position,
            button: slint::platform::PointerEventButton::Left,
        });
        screen.draw();
    };
    window
        .window()
        .dispatch_event(slint::platform::WindowEvent::PointerScrolled {
            position: slint::LogicalPosition::new(100.0, 400.0),
            delta_x: 0.0,
            delta_y: 5000.0,
        });
    screen.draw();
    press(window.get_ask_x(), window.get_ask_y());
    assert!(
        window.get_asking(),
        "the remove button did not ask, at {} {}",
        window.get_ask_x(),
        window.get_ask_y()
    );
    assert_eq!(window.get_removed(), 0, "it removed without asking");
    press(window.get_ask_x(), window.get_ask_y());
    assert_eq!(
        window.get_removed(),
        1,
        "Remove in its place did not remove"
    );
    assert!(!window.get_asking());

    // The list takes the arrow keys: down and up move the pick.
    window.invoke_focus_list();
    for (key, want) in [
        (slint::platform::Key::DownArrow, 1),
        (slint::platform::Key::DownArrow, 2),
        (slint::platform::Key::UpArrow, 1),
    ] {
        let text: slint::SharedString = key.into();
        let w = window.window();
        w.dispatch_event(slint::platform::WindowEvent::KeyPressed { text: text.clone() });
        w.dispatch_event(slint::platform::WindowEvent::KeyReleased { text });
        assert_eq!(
            window.get_stepped(),
            want,
            "the arrow keys do not move the pick"
        );
    }

    // Every size drew the same details: nothing was made again.
    assert_eq!(window.get_made(), 1, "a resize made the details anew");
}
