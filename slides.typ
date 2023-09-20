#import "@preview/polylux:0.3.1": *
#import themes.simple: *

#set text(font: ("Verdana"))
#let matrix_color = rgb("#008F11")
#show link: strong
#show link: set text(fill: blue)
#show: simple-theme.with()

#let slideh(title, body) = {
  let deco-format(it) = text(size: .6em, fill: gray, it)
  set page(
    header: locate(loc => {
      let sections = query(heading.where(level: 1, outlined: true).before(loc), loc)
      let heads = query(heading.where(outlined: true).before(loc), loc)
      if sections == () {
        if title == [] and sections.last().body != heads.last().body {
          deco-format(heads.last().body)
        }
      } else {
        if title == [] and sections.last().body != heads.last().body {
          deco-format(heads.last().body)
        }
        h(1fr)
        deco-format(sections.last().body)
      }
    }),
    footer: deco-format({
      simple-footer.display(); h(1fr); logic.logical-slide.display()
    }),
    footer-descent: 1em,
    header-ascent: 1em,
  )
  set align(horizon)
  let full_body = [
    #align(top, title)
    #align(horizon, body)
  ]
  logic.polylux-slide(full_body)
}

#title-slide[
  = Vulnerability Research of Android apps:\ from 0 to 0-day using fuzzing
  #v(2em)
  #align(center, strong[Defcon Tbilisi | DC995322])
  #table(columns: (auto, auto), stroke: none, column-gutter: 10%,
    [
      GitHub: #link("https://github.com/saruman9")[saruman9]
    ], [
      Telegram: #link("https://t.me/dura_lex")[\@dura_lex]
    ]
  )
  #align(center + bottom)[September 23, 2023]
]


#slideh[== About me][
  - *Vulnerability Researcher*: IoT, ICS, embedded (ATM, CPU, PCH, etc.)
  - *System Developer*: tools for automatic analysis, observability systems, fuzzers, emulators, etc.
]

#slideh[== Background][
  #line-by-line[
    - Money
    - BugBounty
    - Mobile Applications, OSs, HW
    - Test Task
  ]
]

#centered-slide[= Beginning]

#slideh[== Disclaimer][
  - No WEB vulnerabilities
  - No Java vulnerabilities
  - No vulnerabilities in protocols and specifications
  #pause
  - Memory corruptions
  - Binary vulnerabilities
  - RCE and data-only exploits
]

#slideh[][
  Not about exploitation or a specific vulnerability/CVE, but the methodology.
]

#slideh[== APK Analysis][
  What's interesting for me?

  - Android manifest file
    - Activities
    - Services
    - Broadcasts Receivers
    - Content Providers
    - Permissions
]

#slideh[][
  - Resources
    - Libraries
    - DSL parsers
    - Protocol Buffers files
    - Custom binary blobs
]

#slideh[][
  - Java Decompilation
    - Deobfuscation
    - Refactoring
    - Analysis (control-flow, data-flow, etc.)
]

#slideh[][
  - Shared/Native Libraries --- my main target
]

#slideh[== Is source code exist?][
  - Telegram — YES
  - Viber — NO
  - WhatsApp — NO
]

#centered-slide[= Telegram
  #v(2em)
  #image(height: 50%, "./images/Telegram-Logo.png")
]

#slideh[== Why first?][
  #line-by-line[
    - Source Code --- #sym.checkmark
    - BugBounty --- #sym.checkmark
    - I'm a user of the app -- #sym.checkmark
  ]
]

#slideh[== Static Analysis][
  - Manifest file --- #sym.checkmark
  - Resources --- #sym.times
]

#slideh[][
  #set align(center)
  #table(columns: (40%, 20%, 40%), stroke: none,
    [
      - Java
      - C++
    ],
    text(size: 3em, sym.arrow.r.double),
    [Android Studio]
  )
]

#slideh[== Shared/Native libraries][
  Ordered by the "low-hanging fruit" principle:

  + Legacy code
  + Self-written components
  + ...
  5. Crypto implementation
  + ...
  9. Popular open-source frameworks
  + RFC, protocols and manifests
]

#slideh[== Plan][
  + Translate the code architecture into a convenient format (mind map, graph, wiki, Zettelkasten, etc.) #pause
  + Identify the entry points #pause
  + Building attack vectors #pause
  + Isolating target components #pause
  + Analysis (fuzzing in our case)
]

#slideh[== Attack Vectors & Components][
  - File parsers and decoders
    - FLAC
    - GIF
    - Opus
    - Lottie (modified)
]

#slideh[][
  - Connection
    - `tgnet`
    - `TLObject` --- (de)serialization (legacy)
  - VoIP
    - `tgcalls` (legacy)
    - WebRTC (modified)
  - etc.
]

#centered-slide[== Fuzzing]

#slideh[=== Harness][
  #table(columns: (30%, 10%, 20%, 40%), stroke: none,
    [Do you have the source code? #pause], [YES #pause],
    [#text(size: 3em, sym.arrow.r.double)],
    [easy peasy lemon squeezy]
    )
]

#centered-slide[NO]

#slideh[][
  - Isolation is not always possible in complex components #pause
  - Behavior emulation (sockets, files, server, protocol, Java code, etc.) #pause
  - Legacy code is a legacy code #pause
  - Build for Android or for a host x86_64 POSIX machine?
]

#slideh[==== Example. `tgnet`][
  + Replace Android code #pause
  + #strike[Modify]Write CMake file #pause
  + Develop server (MTProto) and emulate Java code & socket file #pause
  + Develop a MitM PoC attack for triaging
]

#slideh[=== Fuzzers][
  - AFL/AFL++
  - libFuzzer / centipede / fuzztest
  - honggfuzz
  - libAFL
  - etc.
]

#slideh[== Catches][
  - DoS
  - Leaks
  - Cryptography weaknesses
  - Vulnerabilities in open source components
]

#slideh[== Summary][
  + Not so interesting for the presentation, but important as a base
  + Bad BugBounty program
  + Good for a first research in this field
  + Many other methods of analysis can be applied
]
