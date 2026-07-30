# Translating luadch

luadch's user-facing strings are translated on Weblate:

**➡️ [translate.dcvault.net](https://translate.dcvault.net/)**

No account setup on your side beyond registering on that instance - just
pick the `luadch` project and start. This page explains how translating
works and how your translations reach the hub.

- [How it works](#how-it-works)
- [How to translate](#how-to-translate)
- [The flow: from Weblate to a release](#the-flow-from-weblate-to-a-release)
- [Adding a new language](#adding-a-new-language)

## How it works

The **Git repository is the source of truth**; Weblate is a bidirectional
mirror on top of it. You never upload files, and you never edit the JSON by
hand - Weblate owns the language files and would overwrite a manual change.

- **English** is the source, authored by maintainers in the repo
  (`lang/en/hub.json` for the hub, `scripts/lang/en/<plugin>.json` per
  plugin). Weblate pulls it automatically.
- **Every other language** is edited in the Weblate web UI. Weblate pushes
  the result back to the repo, where a maintainer merges it.

**English fallback - translations may be incomplete.** Every string is read
as `lang.key or "<English>"`, so an untranslated (or empty) string falls back
to English at runtime. A translation is useful and shippable at any
percentage; a missing string is never a blank message, just English.

## How to translate

1. Open **[translate.dcvault.net](https://translate.dcvault.net/)**, register
   / log in, and pick the `luadch` project and your language (or
   [add one](#adding-a-new-language)).
2. Translate string by string in the web UI. Two rules keep translations
   safe:
   - **Keep every placeholder, in the same order.** `%s` (text) and `%d`
     (number) are filled in at runtime by Lua's `string.format`, which has
     **no positional specifiers** (`%1$s` does not exist and would crash) -
     the placeholders are filled in the order they appear. So keep the same
     number, the same types, and the same order as the English source; if a
     message needs an extra value it is appended at the end. Weblate warns
     you about placeholder mismatches.
   - **Keep DC / ADC jargon in English**, even mid-sentence: *Hub, Slot,
     Share, OP, Kick, Ban, Nick, CID, PID, PM, TLS, ZLIF*. Users expect these
     terms in English.
3. Leave a string untranslated rather than guessing - English fallback beats
   a wrong translation.

That's it. Saving in Weblate is all that is required from a translator.

## The flow: from Weblate to a release

```
   maintainers author EN ──push──▶ dev ──webhook──▶ Weblate
                                    ▲                   │  translators translate
   you merge the PR ◀── weblate branch ◀── Weblate pushes back
```

- Weblate pulls English source from `dev` and pushes translations to a
  dedicated **`weblate`** branch (never straight to `dev`).
- A maintainer merges the `weblate` -> `dev` pull request, so translations
  pass the same review + CI gate as code (the CI checks English is complete
  and consistent with the code, that a translation has no orphan keys, and
  that every translated string keeps its `%s` / `%d` count).
- From `dev` translations ride the normal `dev` -> `master` promotion; there
  is no separate translation release. A hub upgrade ships whatever
  translations exist at that point.

## Adding a new language

In Weblate, open a component and use **Tools -> Start new translation**, pick
the language (e.g. French / `fr`). Weblate creates `lang/fr/hub.json` and
`scripts/lang/fr/<plugin>.json`. No hub code change is needed: the loader
builds the path from `cfg.language`, so once the `fr` files exist an operator
just sets `language = "fr"` in `cfg.tbl`, and untranslated strings fall back
to English.
