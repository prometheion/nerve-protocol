//! A folder and a rule are removed in two clicks (#232): the row's button
//! asks "Remove?" in its place, Cancel keeps the row, and only Remove
//! removes. Clicks on the real page, since a button wired straight to the
//! removal would pass every test that calls the removal itself. One test:
//! Slint takes one platform per process.

use std::cell::RefCell;
use std::rc::Rc;

use nerve::headless::Screen;
use nerve::{AppWindow, FolderRow, Load, Page, Perm, Store};
use slint::platform::{PointerEventButton, WindowEvent};
use slint::{ComponentHandle, LogicalPosition, ModelRc, SharedString, VecModel};

const SIZE: (u32, u32) = (1440, 900);

#[test]
fn a_row_asks_before_it_removes() {
    let screen = Screen::install(SIZE.0, SIZE.1, 1.0).unwrap();
    let window = AppWindow::new().unwrap();
    window.show().unwrap();
    let store = window.global::<Store>();
    let perm = window.global::<Perm>();
    store.set_page(Page::Policy);
    perm.set_centers(ModelRc::new(VecModel::from(vec![SharedString::from(
        "home",
    )])));
    perm.set_center("home".into());
    perm.set_mode("allowlist".into());
    perm.set_read(true);
    perm.set_load(Load::Ready);
    perm.set_folders(ModelRc::new(VecModel::from(vec![FolderRow {
        path: "/srv/project".into(),
        read: true,
        write: false,
        execute: false,
    }])));
    perm.set_allow(ModelRc::new(VecModel::from(vec![SharedString::from(
        "exec.run:make test",
    )])));
    perm.set_allow_unfit(ModelRc::new(VecModel::from(vec![SharedString::new()])));
    // What the page removed, by the callbacks the app's controller serves.
    let removed = Rc::new(RefCell::new(Vec::<String>::new()));
    let r = removed.clone();
    perm.on_folder_remove(move |p| r.borrow_mut().push(p.to_string()));
    let r = removed.clone();
    perm.on_rule_remove(move |_, t| r.borrow_mut().push(t.to_string()));

    let click = |x: f32, y: f32| {
        let position = LogicalPosition::new(x, y);
        let w = window.window();
        w.dispatch_event(WindowEvent::PointerMoved { position });
        w.dispatch_event(WindowEvent::PointerPressed {
            position,
            button: PointerEventButton::Left,
        });
        w.dispatch_event(WindowEvent::PointerReleased {
            position,
            button: PointerEventButton::Left,
        });
    };
    // The first place, from the right edge in, where a click makes `done`
    // true: the row's buttons sit at the list's right end.
    let find = |done: &dyn Fn() -> bool, from: f32, to: f32, rows: (f32, f32)| {
        let mut y = rows.0;
        while y < rows.1 {
            let mut x = from;
            while if to < from { x >= to } else { x <= to } {
                click(x, y);
                screen.draw();
                screen.draw();
                if done() {
                    screen.draw();
                    return (x, y);
                }
                x += if to < from { -14.0 } else { 14.0 };
            }
            y += 12.0;
        }
        panic!("no click got there");
    };
    let w = SIZE.0 as f32;

    for (section, key, what) in [
        (0, "folder:home:/srv/project", "/srv/project"),
        (2, "rule:home:0:exec.run:make test", "exec.run:make test"),
    ] {
        perm.set_section(section);
        screen.draw();
        // The first click on the row's button asks; nothing is removed.
        let asked = || store.get_asking() == key;
        let (x, y) = find(&asked, w - 30.0, w - 150.0, (190.0, 290.0));
        assert!(removed.borrow().is_empty(), "{what} went without asking");
        assert!(!perm.get_folder_open(), "{what}: a click hit Change");
        // Cancel, a little left of Remove, keeps it.
        let cancelled = || store.get_asking().is_empty();
        find(&cancelled, x - 170.0, x - 30.0, (y, y + 1.0));
        assert!(removed.borrow().is_empty(), "{what} went with Cancel");
        assert!(!perm.get_folder_open(), "{what}: a click hit Change");
        // Asked again, the click on Remove removes it, once.
        click(x, y);
        screen.draw();
        screen.draw();
        assert!(asked(), "{what} did not ask again");
        click(x, y);
        screen.draw();
        screen.draw();
        assert_eq!(*removed.borrow(), [what], "{what} was not removed");
        assert!(store.get_asking().is_empty());
        removed.borrow_mut().clear();
    }

    // A question left open belongs to its center and its visit: another
    // center with the same folder does not show it armed, and the page left
    // and come back to asks nothing.
    perm.set_section(0);
    screen.draw();
    let key = "folder:home:/srv/project";
    let (x, y) = find(
        &|| store.get_asking() == key,
        w - 30.0,
        w - 150.0,
        (190.0, 290.0),
    );
    perm.set_center("office".into());
    screen.draw();
    click(x, y);
    screen.draw();
    assert!(
        removed.borrow().is_empty(),
        "another center's folder went at one click"
    );
    assert_eq!(store.get_asking(), "folder:office:/srv/project");
    store.set_page(Page::Log);
    screen.draw();
    store.set_page(Page::Policy);
    screen.draw();
    assert!(
        store.get_asking().is_empty(),
        "the question came back with the page"
    );
}
