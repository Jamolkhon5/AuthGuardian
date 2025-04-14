package services

import (
	"fmt"
	"net/smtp"
)

type EmailService struct {
	smtpHost     string
	smtpPort     string
	smtpUser     string
	smtpPassword string
	fromEmail    string
}

func NewEmailService(smtpHost, smtpPort, smtpUser, smtpPassword, fromEmail string) *EmailService {
	return &EmailService{
		smtpHost:     smtpHost,
		smtpPort:     smtpPort,
		smtpUser:     smtpUser,
		smtpPassword: smtpPassword,
		fromEmail:    fromEmail,
	}
}

func (s *EmailService) SendIPChangeAlert(userEmail, oldIP, newIP string) error {
	// ToDo шаблон для email
	subject := "предупреждениt безопасности"
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>

</html>
`, oldIP, newIP)
	fmt.Printf("Mock sending email to %s: %s\n", userEmail, subject)

	// ToDO бы код отправки email
	// return s.sendEmail(userEmail, subject, body)
	fmt.Println(body)
	//для тестирования просто возвращаем успех
	return nil
}

// sendEmail отправляет email пользователю
func (s *EmailService) sendEmail(to, subject, body string) error {
	auth := smtp.PlainAuth("", s.smtpUser, s.smtpPassword, s.smtpHost)
	headers := make(map[string]string)
	headers["From"] = s.fromEmail
	headers["To"] = to
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=utf-8"
	message := ""
	for key, value := range headers {
		message += fmt.Sprintf("%s: %s\r\n", key, value)
	}
	message += "\r\n" + body
	err := smtp.SendMail(
		s.smtpHost+":"+s.smtpPort,
		auth,
		s.fromEmail,
		[]string{to},
		[]byte(message),
	)

	return err
}
