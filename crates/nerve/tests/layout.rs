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
    import { PageFrame, Split, ListPane, DetailsPane, SidePane, ListCard, ListItem, ListSwitch, RemoveAsk, TextArea } from "../ui/widgets.slint";
    import { Shape, Panes } from "../ui/theme.slint";
    export { Shape, Panes }

    component Probe inherits PageFrame {
        in property <bool> open;
        in property <bool> form;
        in-out property <string> typed;
        in-out property <int> accepted;
        out property <length> area-height: area.height;
        public function focus-area() {
            area.focus();
        }
        public function focus-before() {
            before.focus();
        }
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
        // A field of its own just before the TextArea, to Tab from.
        before := FocusScope {
            width: 10px;
            height: 10px;
        }
        area := TextArea {
            text <=> root.typed;
            one-line: true;
            lines-high: 38px;
            most: 160px;
            accepted => {
                root.accepted += 1;
            }
        }
        switch := ListSwitch {
            options: ["Folders", "Forbidden commands", "Allowed commands", "Sudo"];
            counts: ["4", "2", "3", "Off"];
        }
        split := Split {
            side: true;
            list := ListPane {
                open: root.open;
                share: 0.45;
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
                form: root.form;
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
                least: 300px;
                share: 0.24;
                Rectangle {
                    height: 50px;
                }
            }
        }
    }

    export component Window_ inherits Window {
        in property <bool> open <=> probe.open;
        in property <bool> form <=> probe.form;
        in-out property <string> typed <=> probe.typed;
        out property <int> accepted: probe.accepted;
        out property <length> area-height: probe.area-height;
        public function focus-area() {
            probe.focus-area();
        }
        public function focus-before() {
            probe.focus-before();
        }
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

/// The list and its details as the window changes (#231, #213): side by
/// side wherever both fit at their least widths, a third pane wherever all
/// three do, joined and filling the page at every width from 900 to 2200
/// px; in turns where they do not, with Back to the list; the details in
/// view while the page scrolls a long list; the page's cap; a drag of a
/// divider, its shares kept on a resize, a double-click back to the
/// defaults; and one tree for every size.
#[test]
fn the_list_and_its_details_follow_the_window() {
    let screen = Screen::install(1440, 900, 1.0).unwrap();
    let window = Window_::new().unwrap();
    window.set_rows(40);
    window.show().unwrap();
    let panes = window.global::<Panes>();
    at(&screen, 1440, 900);

    // Side by side: the list at the left, the details right of it, both
    // shown; the list grows with its rows, no scroll of its own.
    assert!(window.get_list_shown() && window.get_details_shown());
    assert!(
        window.get_details_x() > window.get_list_x() + window.get_list_width(),
        "the details are not right of the list"
    );
    assert_eq!(
        window.get_card_height(),
        40.0 * 40.0 + 6.0,
        "the list does not grow with its rows"
    );

    // At every width the panes that fit are shown, each at least its least
    // width, and together they fill the page, with nothing beside them.
    for width in (900..=2200).step_by(100) {
        at(&screen, width, 900);
        let page = window.get_split_width();
        assert_eq!(
            panes.get_width(),
            page,
            "at {width}: the panes know another width"
        );
        let (list, details, side) = (
            window.get_list_width(),
            window.get_details_width(),
            window.get_side_width(),
        );
        assert!(
            list >= 260.0 && details >= 360.0,
            "at {width}: {list} and {details}"
        );
        let three = page >= 300.0 + 260.0 + 360.0 + 2.0 * 16.0;
        assert_eq!(
            side > 0.0,
            three,
            "at {width}: the third pane is {side} wide"
        );
        assert!(
            !three || side >= 300.0 + 16.0,
            "at {width}: the third pane is {side}"
        );
        // The details' gap is their own; the third pane's too.
        let sum = list + 16.0 + details + side;
        assert!((sum - page).abs() < 1.0, "at {width}: {sum} of {page}");
    }

    // Scrolled far down the list, the details stay in view at its top.
    at(&screen, 1440, 900);
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

    // A form in the details takes room from a list that was not dragged.
    let list = window.get_list_width();
    window.set_form(true);
    at(&screen, 1440, 900);
    assert!(
        window.get_list_width() < list - 50.0,
        "the list is {} beside a form, {list} without",
        window.get_list_width()
    );
    window.set_form(false);
    at(&screen, 1440, 900);

    // The divider between the list and the details: a drag moves it, the
    // list gaining what the details give up and the third pane as it was.
    let press = |x: f32, y: f32| {
        window
            .window()
            .dispatch_event(slint::platform::WindowEvent::PointerPressed {
                position: slint::LogicalPosition::new(x, y),
                button: slint::platform::PointerEventButton::Left,
            });
    };
    let release = |x: f32, y: f32| {
        window
            .window()
            .dispatch_event(slint::platform::WindowEvent::PointerReleased {
                position: slint::LogicalPosition::new(x, y),
                button: slint::platform::PointerEventButton::Left,
            });
    };
    let drag = |x: f32, y: f32, dx: f32| {
        press(x, y);
        for step in 1..=10 {
            window
                .window()
                .dispatch_event(slint::platform::WindowEvent::PointerMoved {
                    position: slint::LogicalPosition::new(x + dx * step as f32 / 10.0, y),
                });
            screen.draw();
        }
        release(x + dx, y);
        screen.draw();
    };
    let (list, details, side) = (
        window.get_list_width(),
        window.get_details_width(),
        window.get_side_width(),
    );
    let grip = (window.get_details_x() - 8.0, window.get_details_y() + 20.0);
    drag(grip.0, grip.1, 100.0);
    assert!(
        (window.get_list_width() - (list + 100.0)).abs() < 1.5,
        "the list is {} after a drag of 100 from {list}",
        window.get_list_width()
    );
    assert!((window.get_details_width() - (details - 100.0)).abs() < 1.5);
    assert_eq!(window.get_side_width(), side, "the third pane moved");
    // The drag stops at the details' least width.
    let grip = (window.get_details_x() - 8.0, window.get_details_y() + 20.0);
    drag(grip.0, grip.1, 2000.0);
    assert!(
        (window.get_details_width() - 360.0).abs() < 1.5,
        "the details are {} after a drag past their least width",
        window.get_details_width()
    );
    // A wider window keeps the shares: the list's of the list and the
    // details stays what the drag made it.
    let share = panes.get_list_share();
    assert!(share > 0.0);
    at(&screen, 2000, 900);
    let ratio = window.get_list_width() / (window.get_list_width() + window.get_details_width());
    assert!(
        (ratio - share).abs() < 0.01,
        "{ratio} after a resize, {share} before"
    );
    // A double-click on the divider: the page's defaults again.
    let grip = (window.get_details_x() - 8.0, window.get_details_y() + 20.0);
    for _ in 0..2 {
        press(grip.0, grip.1);
        release(grip.0, grip.1);
    }
    screen.draw();
    assert_eq!(panes.get_list_share(), -1.0, "a double-click kept the drag");

    // The third pane's divider: before the details here, the details give
    // up what it gains and the list stays.
    at(&screen, 1600, 900);
    let (list, side) = (window.get_list_width(), window.get_side_width());
    let grip = (
        window.get_details_x() + window.get_details_width() + 8.0,
        window.get_details_y() + 20.0,
    );
    drag(grip.0, grip.1, -60.0);
    assert!(
        (window.get_side_width() - (side + 60.0)).abs() < 1.5,
        "the third pane is {} after a drag of 60 from {side}",
        window.get_side_width()
    );
    assert!(
        (window.get_list_width() - list).abs() < 1.5,
        "the list moved"
    );
    panes.invoke_reset();

    // A large window: the page keeps margins past its cap.
    at(&screen, 2200, 1200);
    assert!(
        window.get_split_width() > 1900.0 && window.get_split_width() <= 2000.0,
        "the page is {} wide in a window of 2200",
        window.get_split_width()
    );

    // Where the list and the details do not fit side by side, the list
    // fills the page, without the details, until a row opens them; then
    // they take the list's place, and Back goes back.
    at(&screen, 640, 700);
    assert!(window.get_list_shown() && !window.get_details_shown());
    assert!(
        window.get_list_width() > 540.0,
        "the list does not fill the page: {}",
        window.get_list_width()
    );
    window.set_open(true);
    screen.draw();
    assert!(!window.get_list_shown() && window.get_details_shown());
    assert!(window.get_details_width() > 540.0);
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
    window.set_open(false);
    screen.draw();

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
    a_field_grows_with_its_text(&screen, &window);
}

/// A command or JSON field grows with its text up to its most, then
/// scrolls; a one-line one takes Enter as accepted, not as a new line
/// (#213). Part of the test above: Slint takes one platform per process.
fn a_field_grows_with_its_text(screen: &Screen, window: &Window_) {
    at(screen, 1000, 900);
    let one = window.get_area_height();
    assert_eq!(one, 38.0, "one line is {one} high");
    window.set_typed("a-long-command --with many --arguments ".repeat(8).into());
    at(screen, 1000, 900);
    let some = window.get_area_height();
    assert!(some > one + 15.0, "a wrapped command stays {some} high");
    window.set_typed("word ".repeat(2000).into());
    at(screen, 1000, 900);
    assert_eq!(window.get_area_height(), 160.0, "it grows past its most");
    window.set_typed("x".into());
    window.invoke_focus_area();
    let text: slint::SharedString = slint::platform::Key::Return.into();
    let w = window.window();
    w.dispatch_event(slint::platform::WindowEvent::KeyPressed { text: text.clone() });
    w.dispatch_event(slint::platform::WindowEvent::KeyReleased { text });
    assert_eq!(window.get_accepted(), 1, "Enter did not accept");
    assert_eq!(window.get_typed(), "x", "Enter made a new line");

    // Tab goes into the text itself, not to a stop of the field's own:
    // what is typed after one Tab arrives.
    window.set_typed("".into());
    window.invoke_focus_before();
    let key = |text: slint::SharedString| {
        w.dispatch_event(slint::platform::WindowEvent::KeyPressed { text: text.clone() });
        w.dispatch_event(slint::platform::WindowEvent::KeyReleased { text });
    };
    key(slint::platform::Key::Tab.into());
    key("k".into());
    assert_eq!(window.get_typed(), "k", "a Tab stop took the keys");
}
