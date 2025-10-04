# Syslog

The syslog standard uses facilities and severities to categorize messages.

- Facilities: kern, user, mail, daemon, auth, local0, local7
- Severities: emerg, alert, crit, err, warning, notice, info, debug

## Log file

Log file locations are configurable

- /var/log/messages
- /var/log/syslog

The logger utility created user.notice messages by default.

```sh
logger "Message"
logger -p local0.info "Message"
logger -t myscript -p local0.info "Message"
logger -i -t myscript "Message"
```
