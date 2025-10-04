# Break

To restart the loop at the next iteration before the loop completes, we can use
the continue statement. Any commands that follow the continue statement will not
be executed. Execution continues at the top of the loop and the while condition
is examined again.

In this example we loop through a list of MySQL databases.

## Example

```sh
mysql -BNe 'show databases' | while read DB
do
    db-backed-up-recently $DB
    if [ "$?" -eq "0" ]
    then
        continue
    fi
    backup $DB
done
```

- The `-B` option disables the ASCII table output that MySQL normally displays.
- The `-N` option suppresses the column names in the output: this prevents the
  header from being displayed.
- The `-e` option causes MySQL to execute the commands that follow it.

This MySQL command lists one database per line of output. That output is piped
into a while loop. The read command assigns the input to the DB variable.

First, we check if the database has been backed up recently.
`db-backed-up-recently $DB`. This script returns with a 0 if the database has
been backed up in the last 24 hours.

If the database has been backed up recently, we continue the script and the next
database is getting checked by the loop. If the database hasn't been backed up,
we call the script to back it up.
