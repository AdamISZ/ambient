//! Tracing layer that captures INFO messages for the GUI status bar
//!
//! This module provides a tracing Layer that sends INFO-level log messages
//! to a channel, allowing the GUI to display them in the status bar.

use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::OnceLock;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// Global sender for status messages
static STATUS_SENDER: OnceLock<Sender<String>> = OnceLock::new();

/// Global receiver for status messages (taken once by the GUI)
static STATUS_RECEIVER: OnceLock<std::sync::Mutex<Option<Receiver<String>>>> = OnceLock::new();

/// Initialize the status channel and return the Layer
///
/// This should be called once during application startup.
/// The Layer should be added to the tracing subscriber.
pub fn init_status_layer() -> StatusLayer {
    let (sender, receiver) = mpsc::channel();

    STATUS_SENDER.set(sender).expect("Status layer already initialized");
    STATUS_RECEIVER.set(std::sync::Mutex::new(Some(receiver))).expect("Status receiver already set");

    StatusLayer
}

/// Take the status receiver (can only be called once)
///
/// Returns None if already taken or not initialized.
pub fn take_status_receiver() -> Option<Receiver<String>> {
    STATUS_RECEIVER.get()?.lock().ok()?.take()
}

/// Tracing layer that captures INFO messages for the status bar
pub struct StatusLayer;

impl<S: Subscriber> Layer<S> for StatusLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        // Only capture INFO level messages
        if *event.metadata().level() != Level::INFO {
            return;
        }

        // Extract the message from the event
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);

        if let Some(message) = visitor.message {
            // Strip emojis and clean up the message for GUI display
            let cleaned = strip_emojis(&message);
            if !cleaned.is_empty() {
                // Try to send, ignore if channel is full/disconnected
                if let Some(sender) = STATUS_SENDER.get() {
                    let _ = sender.send(cleaned);
                }
            }
        }
    }
}

/// Strip emojis and other non-ASCII decorative characters from a string
fn strip_emojis(s: &str) -> String {
    s.chars()
        .filter(|c| {
            // Keep ASCII and common extended Latin characters
            // Filter out emojis and other Unicode symbols
            let code = *c as u32;
            code < 0x2600 || // Below symbols range
            (code >= 0x2000 && code < 0x2070) // Keep general punctuation but not symbols
        })
        .collect::<String>()
        .trim()
        .to_string()
}

/// Visitor to extract the message field from a tracing event
#[derive(Default)]
struct MessageVisitor {
    message: Option<String>,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{:?}", value));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        }
    }
}
