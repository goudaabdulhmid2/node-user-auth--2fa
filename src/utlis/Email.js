const nodemailler = require("nodemailer");
const catchAsync = require("express-async-handler");

const ApiError = require("./ApiError");

class Email {
  constructor(user, code) {
    this.to = user.email;
    this.firstname = user.name.split(" ")[0];
    this.code = code;
    this.from = `HealthMate team`;
  }

  // Create
  newTransport() {
    return new nodemailler.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      secure: true,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
      },
      tls: {
        rejectUnauthorized: false,
      },
      // Add rate limiting
      pool: true,
      maxConnections: 5,
      maxMessages: 100,
      rateDelta: 1000,
      rateLimit: 5,
    });
  }

  send = catchAsync(async (message, subject) => {
    const mailOptions = {
      from: this.from,
      to: this.to,
      subject,
      text: message,
    };

    const transport = this.newTransport();
    const result = await transport.sendMail(mailOptions);

    if (!result) {
      console.error("Email sending error:", error);
      throw new ApiError("Failed to send email", 500);
    }

    transport.close();
    return result;
  });

  // Password reset email
  async senPasswordReset() {
    const message = `
    Hello ${this.firstname},
    
    We received a request to reset your password on HealthMate Account.
    
    Please use the code to reset your password:
    ${this.code}
    
    This code is valid for 10 minutes only.
    
    If you didn't request this reset, please ignore this email or contact support.
    
    Thanks for helping us keep your account secure.
    
    Best regards,
    HealthMate Team
  `;

    await this.send(
      message,
      "Your password reset token (valid for onlt 10 minutes)"
    );
  }

  // Welcome email to new user
  async sendWelcome() {
    const message = `
      Hi, ${this.firstname}
      
      Welcome to the HealthMate Family!
      
      You've successfully registered, and your journey with us has just begun.
      
      If you have any questions, our support team is here to help.
      
      Enjoy your journey with us!
      
      Best regards,
      HealthMate Team
    `;
    await this.send(message, "Welcome to the HealthMate Family!");
  }

  // Verify Email
  async sendVerifyEmail() {
    const message = `
      Hi, ${this.firstname}
      
      Welcome to the HealthMate Family!
      
      To verify your email, please click the following link:
      ${this.code}
      
      Best regards,
      HealthMate Team
    `;
    await this.send(message, "Verify Your Email!.");
  }

  // Two factor recovery email
  async sendTwoFactorRecovery() {
    const message = `
    Hello ${this.firstname},
    
    We received a request to Two Factor Recovery.
    
    Please use the code to complete your Recovery:
    ${this.code}
    
    This code is valid for 5 minutes only.
    
    If you didn't request this reset, please ignore this email or contact support.
    
    Thanks for helping us keep your account secure.
    
    Best regards,
    HealthMate Team
  `;

    await this.send(
      message,
      "Your recovery reset code (valid for only 5 minutes)"
    );
  }
}

module.exports = Email;
