package main

import "gopkg.in/gomail.v2"

func (u *User) sendEmail(htmlContent, subject, to string) error {
	mail := gomail.NewMessage()
	mail.SetHeader("From", MailSend)
	mail.SetHeader("To", to)
	mail.SetHeader("Subject", subject)

	mail.SetBody("text,html", htmlContent)

	deal := gomail.NewDialer("stmp.gmail.com", 587, MailSend, MailPassSend)
	if err := deal.DialAndSend(mail); err != nil {
		return err
	}

	return nil
}
