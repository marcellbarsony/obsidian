# Arparse

- [Parse command line options](https://docs.python.org/3/library/argparse.html)

```py
import argparse

# Initialize
parser = argparse.ArgumentParser(
                    prog = 'ProgramName',
                    description = 'Description',
                    epilog = 'Text at the bottom of help')

# Add argument
parser.add_argument('filename', type=file, metavar='', required=True, help='File')           # positional argument
parser.add_argument('-c', '--count', type=int)      # option that takes a value
parser.add_argument('-v', '--verbose',
                    action='store_true')  # on/off flag

# Run parser
args = parser.parse_args()
# Print arguments
print(args.filename, args.count, args.verbose)
```
