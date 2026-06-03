//! Send OTP emails via SMTP (lettre).

use crate::config::SmtpConfig;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use std::time::Duration;

/// Send a single OTP email to the given address. Builds a new SMTP connection per call.
pub async fn send_otp_email(
    smtp: &SmtpConfig,
    to_email: &str,
    code: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let from_addr = smtp.from.parse()?;
    let to_addr = to_email.parse()?;

    let body = format!(
        "Your login verification code is: {}.\n\nThis code expires in 10 minutes. If you did not request this, please ignore this email.",
        code
    );

    let message = Message::builder()
        .from(from_addr)
        .to(to_addr)
        .subject("Your login verification code")
        .header(ContentType::TEXT_PLAIN)
        .body(body)?;

    // Port 465 = SMTPS (direct TLS); 587/25 = STARTTLS (plain then upgrade). Wrong transport causes "wrong version number" SSL errors.
    let mut builder = if smtp.port == 465 {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp.host)?
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp.host)?
    };

    builder = builder.port(smtp.port).timeout(Some(Duration::from_secs(30)));

    if let (Some(u), Some(p)) = (&smtp.user, &smtp.pass) {
        builder = builder.credentials(Credentials::new(u.clone(), p.clone()));
    }

    let mailer = builder.build();
    mailer.send(message).await?;
    Ok(())
}

/// Send password reset email. When `reset_link` is `Some`, the email contains a
/// clickable link; otherwise it falls back to sending the raw `token` (for callers
/// with no configured base URL).
pub async fn send_password_reset_email(
    smtp: &SmtpConfig,
    to_email: &str,
    token: &str,
    reset_link: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let from_addr = smtp.from.parse()?;
    let to_addr = to_email.parse()?;

    let body = match reset_link {
        Some(link) => format!(
            "You requested a password reset. Click the link below to set a new password:\n\n{}\n\nThis link expires in 1 hour. If you did not request this, please ignore this email.",
            link
        ),
        None => format!(
            "You requested a password reset. Use the following token to set a new password:\n\n{}\n\nThis token expires in 1 hour. If you did not request this, please ignore this email.",
            token
        ),
    };

    let message = Message::builder()
        .from(from_addr)
        .to(to_addr)
        .subject("Password reset")
        .header(ContentType::TEXT_PLAIN)
        .body(body)?;

    let mut builder = if smtp.port == 465 {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp.host)?
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp.host)?
    };

    builder = builder.port(smtp.port).timeout(Some(Duration::from_secs(30)));

    if let (Some(u), Some(p)) = (&smtp.user, &smtp.pass) {
        builder = builder.credentials(Credentials::new(u.clone(), p.clone()));
    }

    let mailer = builder.build();
    mailer.send(message).await?;
    Ok(())
}

