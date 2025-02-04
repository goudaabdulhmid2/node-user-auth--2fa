const twilio = require("twilio");
const ApiError = require("./ApiError");

class SMS {
  constructor(user, otp) {
    this.to = this.sanitizePhoneNumber(user.phone);
    this.firstname = user.name.split(" ")[0];
    this.otp = otp;
    this.from = process.env.TWILIO_PHONE_NUMBER;
    this.client = this.initTwilioClient();
  }

  initTwilioClient() {
    try {
      return twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN, {
        lazyLoading: true,
        timeout: 5000, // 5 second timeout
      });
    } catch (error) {
      throw new ApiError("Failed to initialize SMS service", 500);
    }
  }

  sanitizePhoneNumber(phone) {
    // Ensure it starts with +
    return phone.startsWith("+") ? phone : `+${phone}`;
  }

  async send(message) {
    try {
      const response = await this.client.messages.create({
        body: message,
        from: this.from,
        to: this.to,
      });

      return response;
    } catch (error) {
      console.error("SMS sending error:", error);
      const errorMessage = this.getErrorMessage(error);
      throw new ApiError(errorMessage, error.status || 500);
    }
  }

  getErrorMessage(error) {
    // Map Twilio error codes to user-friendly messages
    const errorMessages = {
      21211: "Invalid phone number",
      21408: "Cannot send SMS to this number",
      21610: "Message cannot be empty",
      21614: "Invalid message content",
    };

    return errorMessages[error.code] || "Failed to send SMS";
  }

  async sendTwoFactorRecovery() {
    const message = `
    HealthMate: Your 2FA recovery code is: ${this.otp}
    
    Valid for 5 minutes only.
    
    Don't share this code with anyone.
    
    Ignore if you didn't request this.
  `;

    return await this.send(message);
  }
}

module.exports = SMS;
