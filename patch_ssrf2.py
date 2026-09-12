import re

with open("scanner/rules/ssrf.yml", "r") as f:
    content = f.read()

# I will add an exception for the exact new shape of controlplane
old_tail = r'''(?!(?:(?!\bset_webhook\b).){0,800}(?m:^(?P<guard_indent>[ \t]*)if\s+(?:(?!\bnot\b)[^\n:]){0,400}_is_safe_url\s*\(\s*(?P=webhook_url_var)\s*\)[^\n:]{0,100}:\s*(?:#[^\n]*)?\n(?:(?P=guard_indent)[ \t]+[^\n]*\n){0,20}?(?P=guard_indent)[ \t]+\bset_webhook\s*\(\s*[^,\n]+,\s*[^,\n]+,\s*(?P=webhook_url_var)\s*\)))(?!(?:(?!\bset_webhook\b).){0,800}(?m:^(?P<try_indent>[ \t]*)try\s*:\s*(?:#[^\n]*)?\n(?:(?P=try_indent)[ \t]+[^\n]*\n){0,20}?(?P=try_indent)[ \t]+\bset_webhook\s*\(\s*[^,\n]+,\s*[^,\n]+,\s*(?P=webhook_url_var)\s*\)))(?:(?!\bset_webhook\b).){0,800}?\bset_webhook\s*\(\s*[^,\n]+,\s*[^,\n]+,\s*(?P=webhook_url_var)\s*\))' '''

new_tail = r'''(?!(?:(?!\bset_webhook\b).){0,800}(?m:^(?P<guard_indent>[ \t]*)if\s+(?:(?!\bnot\b)[^\n:]){0,400}_is_safe_url\s*\(\s*(?P=webhook_url_var)\s*\)[^\n:]{0,100}:\s*(?:#[^\n]*)?\n(?:(?P=guard_indent)[ \t]+[^\n]*\n){0,20}?(?P=guard_indent)[ \t]+\bset_webhook\s*\(\s*[^,\n]+,\s*[^,\n]+,\s*(?P=webhook_url_var)\s*\)))(?!(?:(?!\bset_webhook\b).){0,800}(?m:^(?P<try_indent>[ \t]*)try\s*:\s*(?:#[^\n]*)?\n(?:(?P=try_indent)[ \t]+[^\n]*\n){0,20}?(?P=try_indent)[ \t]+\bset_webhook\s*\(\s*[^,\n]+,\s*[^,\n]+,\s*(?P=webhook_url_var)\s*\)))(?!(?:(?!\bset_webhook\b).){0,800}(?m:^(?P<reject2_indent>[ \t]*)if\s+(?:(?P=webhook_url_var)\s+not\s+in\s*\(\s*None\s*,\s*["\x27]["\x27]\s*\)\s+and\s*\(\s*not\s+isinstance\s*\(\s*(?P=webhook_url_var)\s*,\s*str\s*\)\s+or\s+not\s+_is_safe_url\s*\(\s*(?P=webhook_url_var)\s*\)\s*\))(?:(?!:).){0,100}:\s*(?:#[^\n]*)?\n(?:(?P=reject2_indent)[ \t]+[^\n]*\n){0,20}?(?P=reject2_indent)[ \t]+\b(?:return|raise)\b))(?:(?!\bset_webhook\b).){0,800}?\bset_webhook\s*\(\s*[^,\n]+,\s*[^,\n]+,\s*(?P=webhook_url_var)\s*\))' '''

content = content.replace(old_tail.strip(), new_tail.strip())

with open("scanner/rules/ssrf.yml", "w") as f:
    f.write(content)
