const nodemailer = require("nodemailer");
const Mailgen = require("mailgen");

let config = {
  service: "gmail",
  auth: {
    user: process.env.EMAIL,
    pass: process.env.PASSWORD,
  },
};

let transporter = nodemailer.createTransport(config);

let MailGenerator = new Mailgen({
  theme: "default",
  product: {
    name: "UDINPARTAI",
    link: "https://google.com",
  },
});

const registerMail = async (req, res) => {
  const { username, userEmail, text, subject } = req.body;

  const email = {
    body: {
      name: username,
      intro: text || "Mang Udin for president 2024!",
      outro: "Have questions regarding Mang Udin? Reply to this email.",
    },
  };

  const emailBody = MailGenerator.generate(email);

  let message = {
    from: process.env.EMAIL,
    to: userEmail,
    subject: subject,
    html: emailBody,
  };

  transporter
    .sendMail(message)
    .then(() => {
      return res
        .status(200)
        .json({ msg: "You should receive an email from us" });
    })
    .catch((error) => res.status(500).json({ error: error.message }));
};

module.exports = registerMail;
