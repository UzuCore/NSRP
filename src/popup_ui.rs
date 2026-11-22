//! Nonblocking, consistently styled NSRP message and confirmation dialogs.
//!
//! All callers run on Slint's event-loop thread. File/folder pickers retain
//! their native Windows implementation; this queue replaces message boxes,
//! including confirmations whose answer controls destructive operations.
use crate::AppWindow;
use slint::ComponentHandle;
use std::{cell::RefCell, collections::VecDeque};

type Answer = Box<dyn FnOnce(bool)>;

struct PopupRequest {
    title: String,
    message: String,
    confirm: bool,
    answer: Option<Answer>,
}

#[derive(Default)]
struct PopupState {
    active: Option<PopupRequest>,
    waiting: VecDeque<PopupRequest>,
}

// NSRP is single-instance and Slint UI calls are thread-confined. A
// thread-local queue permits closures that capture UI-only (non-Send)
// resources, without introducing nested blocking event loops.
thread_local! {
    static POPUPS: RefCell<PopupState> = RefCell::new(PopupState::default());
}

pub(crate) fn wire(window: &AppWindow) {
    POPUPS.with(|state| *state.borrow_mut() = PopupState::default());
    window.set_popup_open(false);
    let weak = window.as_weak();
    window.on_popup_response(move |accepted| {
        if let Some(ui) = weak.upgrade() {
            respond(&ui, accepted);
        }
    });
}

pub(crate) fn notice(ui: &AppWindow, title: impl Into<String>, message: impl Into<String>) {
    enqueue(
        ui,
        PopupRequest {
            title: title.into(),
            message: message.into(),
            confirm: false,
            answer: None,
        },
    );
}

pub(crate) fn confirm(
    ui: &AppWindow,
    title: impl Into<String>,
    message: impl Into<String>,
    answer: impl FnOnce(bool) + 'static,
) {
    enqueue(
        ui,
        PopupRequest {
            title: title.into(),
            message: message.into(),
            confirm: true,
            answer: Some(Box::new(answer)),
        },
    );
}

fn enqueue(ui: &AppWindow, request: PopupRequest) {
    POPUPS.with(|state| state.borrow_mut().waiting.push_back(request));
    show_next(ui);
}

fn show_next(ui: &AppWindow) {
    // Do not replace a prompt awaiting a user decision.
    if ui.get_popup_open() {
        return;
    }
    let display = POPUPS.with(|state| {
        let mut state = state.borrow_mut();
        if state.active.is_some() {
            return None;
        }
        let next = state.waiting.pop_front()?;
        let display = (next.title.clone(), next.message.clone(), next.confirm);
        state.active = Some(next);
        Some(display)
    });
    if let Some((title, message, confirm)) = display {
        ui.set_popup_title(title.into());
        ui.set_popup_message(message.into());
        ui.set_popup_confirm(confirm);
        ui.set_popup_open(true);
    }
}

fn respond(ui: &AppWindow, accepted: bool) {
    let active = POPUPS.with(|state| state.borrow_mut().active.take());
    let Some(mut active) = active else {
        return; // Ignore duplicate or stale clicks.
    };
    ui.set_popup_open(false);
    if let Some(answer) = active.answer.take() {
        // Callback may enqueue the next confirmation. The queue advances
        // only after this decision and never duplicates a destructive action.
        answer(accepted);
    }
    show_next(ui);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage68_message_queue_is_fifo_and_answers_are_optional() {
        let mut state = PopupState::default();
        for i in 0..10 {
            state.waiting.push_back(PopupRequest {
                title: format!("title-{i}"),
                message: format!("details-{i}"),
                confirm: i % 2 == 0,
                answer: None,
            });
        }
        for i in 0..10 {
            let next = state.waiting.pop_front().expect("all enqueued popups");
            assert_eq!(next.title, format!("title-{i}"));
            assert_eq!(next.message, format!("details-{i}"));
            assert_eq!(next.confirm, i % 2 == 0);
        }
        assert!(state.waiting.is_empty());
    }
}
