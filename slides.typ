#import "@preview/polylux:0.3.1": *
#import themes.simple: *

#let matrix_color = rgb("#008F11")
#show link: strong
#show link: set text(fill: blue)
#show: simple-theme.with()
#let slideh(title, body) = slide[
  #title
  #set align(horizon)
  #body
]

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

#centered-slide[== Beginning]

#slideh[=== Disclaimer][
  - No WEB vulnerabilities
  - No Java vulnerabilities
  - No vulnerabilities in protocols and specifications
  #pause
  - Memory corruptions
  - Binary vulnerabilities
  - RCE and data-only exploits
]

#slideh[=== APK Analysis][

]
