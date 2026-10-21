# Script for the README's demo GIF, recorded with VHS (https://github.com/charmbracelet/vhs).
# VHS types these commands into a real terminal and saves the result as a GIF.
#
# To re-record, from the SecretScanner folder (with secretscan installed in .venv):
#     vhs demo/demo.tape
#
# Lines starting with # are comments. `Hide`/`Show` turn recording off and on,
# so setup steps don't appear in the GIF. `Sleep` pauses so viewers can read.

Output demo/demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1100
Set Height 560
Set Padding 24
Set TypingSpeed 45ms
Set Theme "Catppuccin Mocha"

# Off camera: create a throwaway repo containing settings.py (see setup.sh).
Hide
Type "source demo/setup.sh" Enter
Sleep 1s
Show

# 1. A settings file with an AWS key and a database password hard-coded in it.
Type "# settings.py has an AWS key and a password hard-coded in it." Enter
Sleep 800ms
Type "git add settings.py" Enter
Sleep 600ms
Type 'git commit -m "Add database settings"' Enter
Sleep 4.5s

# 2. Fix it off camera: read both secrets from environment variables instead.
# `clear` wipes the typed command too, since hidden typing stays on screen.
Hide
Type `printf 'import os\n\n# Database and AWS settings\nAWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]\nDB_PASSWORD = os.environ["DB_PASSWORD"]\n' > settings.py && clear` Enter
Sleep 500ms
Show

Type "# Fixed: the secrets now come from environment variables." Enter
Sleep 600ms
Type "cat settings.py" Enter
Sleep 2.5s
Type 'git add settings.py && git commit -q -m "Add database settings"' Enter
Sleep 1.5s
# Proof the commit was saved this time.
Type "git log --oneline" Enter
Sleep 3s
