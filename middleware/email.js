require("dotenv").config();
const nodemailer = require("nodemailer");

// ===================== EMAIL CONFIG =====================
const emailTransporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "smtp.gmail.com",
  port: process.env.SMTP_PORT || 587,
  secure: process.env.SMTP_SECURE === "true",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
  tls: {
    rejectUnauthorized: false,
  },
});


// ===================== FORGOT PASSWORD =====================

async function sendResetPasswordEmail(email, resetToken) {
  const appUrl = process.env.APP_URL || "http://localhost:3000";
  const resetUrl = `${appUrl}/reset-password?token=${resetToken}&email=${email}`;

  const mailOptions = {
    from: process.env.SMTP_FROM || "noreply@yourapp.com",
    to: email,
    subject: "Reset your password",
    html: `
      <h2>Password Reset Request</h2>
      <p>You requested to reset your password. Click the link below:</p>
      <a href="${resetUrl}" style="padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">Reset Password</a>
      <p>Or copy and paste this link: ${resetUrl}</p>
      <p>This link expires in 1 hour.</p>
      <p>If you didn't request this, please ignore this email.</p>
    `,
  };

  try {
    await emailTransporter.sendMail(mailOptions);
    console.log(`Password reset email sent to ${email}`);
    return true;
  } catch (err) {
    console.error("Failed to send reset password email:", err);
    return false;
  }
}

async function sendVerificationEmail(email, verificationToken) {
  const appUrl = process.env.APP_URL || "http://localhost:3000";
  const verificationUrl = `${appUrl}/verify-otp?token=${verificationToken}&email=${email}`;

  const mailOptions = {
    from: process.env.SMTP_FROM || "noreply@yourapp.com",
    to: email,
    subject: "Verify your email address",
    html: `
      <h2>Email Verification</h2>
      <p>Please click the link below to verify your email address:</p>
      <a href="${verificationUrl}" style="padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">Verify Email</a>
      <p>Or copy and paste this link: ${verificationUrl}</p>
      <p>This link expires in 24 hours.</p>
    `,
  };

  try {
    await emailTransporter.sendMail(mailOptions);
    console.log(`Verification email sent to ${email}`);
    return true;
  } catch (err) {
    console.error("Failed to send verification email:", err);
    return false;
  }
}

module.exports = {
  sendResetPasswordEmail,
  sendVerificationEmail,
};