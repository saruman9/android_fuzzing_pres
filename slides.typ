#import "@preview/polylux:0.3.1": *
#import themes.simple: *

#set text(font: ("Verdana", "Apple Color Emoji"))
#show link: strong
#show link: set text(fill: blue)
#show: simple-theme.with()
#show raw: set text(font: "JetBrainsMono NF")
#show raw.where(block: true): it => {
  if it.text.first() == "$" {
    block(fill: luma(200), inset: 10pt, radius: 4pt, it)
  } else {
    block(fill: luma(240), inset: 10pt, radius: 4pt, it)
  }
}
#show figure.caption: emph
#set figure(numbering: none)
#show footnote.entry: set text(size: 0.7em)
#set footnote.entry(gap: 0.3em)
#show footnote: set text(blue)

#let slideh(title, body) = {
  let deco-format(it) = text(size: .6em, fill: gray, it)
  set page(
    header: context {
      let sections = query(heading.where(level: 1, outlined: true).before(here()))
      let heads = query(heading.where(outlined: true).before(here()))
      if sections == () {
        if title == [] and sections.last().body != heads.last().body {
          deco-format(heads.last().body)
        }
      } else {
        if title == [] and sections.last().body != heads.last().body {
          deco-format(heads.last().body)
        }
        if title == [] or title.at("depth") != 1 {
          h(1fr); deco-format(sections.last().body)
        }
      }
    },
    footer: context {
      deco-format({ simple-footer.get(); h(1fr); logic.logical-slide.display() })
    },
    footer-descent: 1em,
    header-ascent: 1em,
  )
  set align(horizon)
  let full_body = [
    #counter(footnote).update(0)
    #align(top, title)
    #align(horizon, body)
  ]
  logic.polylux-slide(full_body)
}

#title-slide[
  = Vulnerability Research of Android apps:\ from 0 to 0-day using fuzzing
  #v(2em)
  #align(center, strong[DEF CON Russia | DCG7812])
  #table(columns: (auto, auto), stroke: none, column-gutter: 10%,
    [ GitHub: #link("https://github.com/saruman9")[saruman9] ],
    [ Telegram: #link("https://t.me/dura_lex")[\@dura_lex] ]
  )
  #align(center + bottom)[August 10, 2024]
]


#slideh[== About me][
  - *Vulnerability Researcher*: IoT, ICS, embedded, mobile, etc.
  - *System Developer*: tools for automatic analysis, observability systems, fuzzers, emulators, etc.
]

#slideh[== Agenda ][
  #outline(title: none)
  #text(size: .5em, fill: gray, [The further down the list, the more difficult it is...])
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

#focus-slide[
  Not about exploitation or a specific vulnerability/CVE, but the methodology

  #text(size: .5em, fill: gray, [Without meme, sry #emoji.face.tear])
]

#slideh[== APK Analysis][
  What's interesting for me?

  Android manifest file:
    - Activities
    - Services
    - Broadcasts Receivers
    - Content Providers
    - Permissions
]

#slideh[][
  Resources:
    - Libraries
    - DSL parsers
    - Protocol Buffers files
    - Custom binary blobs
]

#slideh[][
  Java Decompilation:
    - Deobfuscation
    - Refactoring
    - Analysis (control-flow, data-flow, etc.)
]

#slideh[][
  Shared/Native Libraries --- my main target
]

#slideh[== Is source code exist?][
  - Telegram — YES
  - Viber — NO
  - WhatsApp — NO
]

#centered-slide[= Telegram
  #v(2em)
  #image(height: 50%, "./images/Telegram_2019_Logo.svg")
]

#slideh[== Why first?][
  #line-by-line[
    - Source Code --- #emoji.checkmark.box
    - BugBounty --- #emoji.checkmark.box
    - I'm a user of the app --- #emoji.checkmark.box
  ]
]

#slideh[== Static Analysis][
  - Manifest file --- #emoji.checkmark.box
  - Resources --- #emoji.crossmark
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
  + Identify the entry points and sinks #pause
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
  #table(columns: (30%, 15%, 15%, 40%), stroke: none,
    [Do you have the source code? #pause], [YES #emoji.checkmark.box #pause],
    [#text(size: 3em, sym.arrow.r.double)],
    [easy peasy lemon squeezy?..]
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
  + Replace Android code
  + #strike[Modify]Write CMake file
  + Develop server #footnote[https://github.com/saruman9/tg_srv] (MTProto #footnote[https://github.com/saruman9/010_editor_templates]) and emulate Java code & socket file
  + Develop a MitM PoC attack for triaging
]

#slideh[=== Fuzzers][
  - AFL/AFL++
  - libFuzzer / centipede / fuzztest
  - honggfuzz
  - LibAFL
  - etc.
]

#slideh[== Catches][
  - DoS
  - Leaks
  - Cryptography weaknesses
  - Vulnerabilities in open source components
]

#slideh[== Summary][
  - Not so interesting for the presentation, but important as a base
  - Not good BugBounty program
  - Good for a first research in this field
  - Many other methods of analysis can be applied
]

#centered-slide[= Viber
  #v(2em)
  #image(width: 80%, "./images/Rakuten_Viber_logo_2020.svg")
]

#slideh[== Sources][
  - Препарируем Viber. Мини-гид по анализу приложений для Android #footnote[https://xakep.ru/2023/05/16/analyzing-viber/] #sym.copyright _Хакер_
  - fuzzer + harness  #footnote[https://github.com/saruman9/viber_linkparser_fuzzer/]
]

#slideh[== Static Analysis][
  - Manifest file --- #emoji.checkmark.box
  - Resources --- #emoji.crossmark
  - 1-day analysis + binary diffing --- #emoji.checkmark.box
]

#centered-slide[== Shared/Native Libraries]

#slideh[=== Architecture --- x86_64][
  - More tools
  - Emulation at high speeds
  - Partial analysis on a host machine
]

#slideh[=== Native functions][
  #only(1)[
    - IDA Pro
    - Binary Ninja
    - rizin
  ]
  #only(2)[
    - #strike[IDA Pro]
    - #strike[Binary Ninja]
    - #strike[rizin]
  ]
]

#slideh[][
  ```shell
  $ readelf -W --demangle --symbols $(LIBRARY_SO) | \
  tail -n +4 | \
  sort -k 7 | \
  # optional rg "FUNC.*Java_.*"
  less
  ```
  #text(0.48em)[
    ```text
    33: 0000000000001bb5    55 FUNC    GLOBAL DEFAULT   13 Java_com_viber_libnativehttp_HttpEngine_nativeCreateHttp
    34: 0000000000001bec    15 FUNC    GLOBAL DEFAULT   13 Java_com_viber_libnativehttp_HttpEngine_nativeDelete
    38: 0000000000001bfb   622 FUNC    GLOBAL DEFAULT   13 Java_com_viber_libnativehttp_HttpEngine_nativeTest
    44: 00000000000018c3   109 FUNC    GLOBAL DEFAULT   13 Java_com_viber_libnativehttp_NativeDownloader_nativeOnConnected
    39: 00000000000015e8   366 FUNC    GLOBAL DEFAULT   13 Java_com_viber_libnativehttp_NativeDownloader_nativeOnData
    35: 0000000000001b0c    40 FUNC    GLOBAL DEFAULT   13 Java_com_viber_libnativehttp_NativeDownloader_nativeOnDisconnected
    40: 0000000000001930   476 FUNC    GLOBAL DEFAULT   13 Java_com_viber_libnativehttp_NativeDownloader_nativeOnHead
    ```
  ]
]

#slideh[][
  ```shell
  $ rg "native.*nativeCreateHttp"
  ```

  ```text
  app/src/main/java/com/viber/libnativehttp/HttpEngine.java
  9:    public static native long nativeCreateHttp();
  ```
]

#slideh[][
  Goals:
  - Find open source components
  - Find the target library
  - Superficial analysis
]

#slideh[== Attack Vectors & Components][
  - Link parser
  - SVG
  - Viber RTC (WebRTC)
  - VoIP engine
]

#centered-slide[== Accessibility (real sink?)]

#slideh[=== Static Analysis][
  - jadx #footnote[https://github.com/skylot/jadx] --- decompilation IntelliJ IDEA --- deobfuscation, refactoring
  - SciTools Understand #footnote[https://www.scitools.com/] --- code-flow, data-flow analysis
  - `strings`/`rizin`, `grep`/`ripgrep`
]

#slideh[][
  #figure(
    image("./images/understand.png", height: 80%),
    caption: [Call graph of SVG native function in Understand],
  )
]

#slideh[=== Dynamic Analysis][
  - Frida and public scripts
  - `frida-trace`
  - Smali patching
  - Binary patching
]

#centered-slide[== Fuzzing]

#slideh[=== Greybox is more interesting][
  #only(1)[- libFuzzer / centipede / fuzztest] #only("2-")[- #strike[libFuzzer / centipede / fuzztest]]
  #only(3)[- honggfuzz] #only("4-")[- #strike[honggfuzz]]
  #only("5-")[- AFL++]
  #only("6-")[- LibAFL]
  #only("6-")[- etc.]
]

#slideh[][
  #set align(center)
  #table(columns: (auto, auto, auto, auto),
    align: (center, center, center),
    stroke: gray,
    inset: .3em,
    [*Fuzzer*], [*Instru\-mentation*], [*Emulator (x86_64)*], [*Real device, aarch64*],
    [AFL++ #footnote[#link("https://blog.quarkslab.com/android-greybox-fuzzing-with-afl-frida-mode.html")[Android greybox fuzzing with AFL++ Frida mode] by Eric Le Guevel from Quarkslab]], [Frida], [#emoji.checkmark.box AFL++ in], [#emoji.checkmark.box],
    [AFL++ #footnote[#link("https://alephsecurity.com/2021/11/16/fuzzing-qemu-android/")[AFL++ on Android with QEMU support] by Itai Greenhut (\@Gr33nh4t) from Aleph Research; #link("https://github.com/marcinguy/fpicker-aflpp-android")[fpicker-aflpp-android] by marcinguy]], [Qemu], [#emoji.crossmark], [#emoji.checkmark.box],
    [AFL++ #footnote[#link("https://googleprojectzero.blogspot.com/2020/07/mms-exploit-part-2-effective-fuzzing-qmage.html")[MMS Exploit Part 2: Effective Fuzzing of the Qmage Codec] by Mateusz Jurczyk from Project Zero; #link("https://github.com/ant4g0nist/Sloth")[Sloth] by ant4g0nist]], [Qemu], [#emoji.checkmark.box], [#emoji.crossmark],
    [AFL++], [Unicorn + qiling], [Unicorn], [#emoji.crossmark/#emoji.checkmark.box?],
    [honggfuzz/AFL++], [QBDI], [QBDI], [#emoji.crossmark/#emoji.checkmark.box?],
    [LibAFL], [Qemu], [#emoji.crossmark], [#emoji.checkmark.box],
    [LibAFL], [Qemu], [#emoji.checkmark.box], [#emoji.crossmark],
    [LibAFL], [Frida], [#emoji.checkmark.box LibAFL in], [#emoji.checkmark.box],
  )
]

#slideh[=== LibAFL + Frida][
  Why? #text(size: .5em, fill: gray, [Later we will review the remaining options])

  - I'm Rust developer
  - I've already used LibAFL
  - Frida is true cross platform software
  - Rust is better for cross-compilation #footnote[not for Android, but not because Rust is bad]
]

#centered-slide[== Harness]

#slideh[=== Reverse Engineering][
  Ghidra

  - Ghidra fork #footnote[https://github.com/saruman9/ghidra]
  - `ghidra_scripts` #footnote[https://github.com/saruman9/ghidra_scripts]
  - Recaster plugin #footnote[https://github.com/saruman9/recaster]
  - "Ghidra. Dev" presentation #footnote[https://github.com/saruman9/ghidra_dev_pres]
]

#slideh[][
  - Binary Ninja --- `binja_snippets` #footnote[https://github.com/saruman9/binja_snippets]
  - IDA Pro
  - rizin
]

#slideh[==== C++][
  Ghidra

  - `RecoverClassesFromRTTIScript.java`
  - `ApplyClassFunctionSignatureUpdatesScript.java`
  - `ApplyClassFunctionDefinitionUpdatesScript.java`
  - C++ directory in Script Manager
  - Ghidra-Cpp-Class-Analyzer #footnote[https://github.com/astrelsky/Ghidra-Cpp-Class-Analyzer] by astrelsky
]

#slideh[][
  IDA Pro

  - ida_medigate #footnote[https://github.com/Metadorius/ida_medigate] by Metadorius --- fork of fork of fork...
  - Referee #footnote[https://github.com/joeleong/ida-referee] by joeleong --- a python port of James Koppel's Referee
]

#slideh[][
  Binary Ninja

  - Use development release channel
  - ClassyPP #footnote[https://github.com/CySHell/ClassyPP] by CySHell
  - binja_itanium_cxx_abi #footnote[https://github.com/whitequark/binja_itanium_cxx_abi] by whitequark
]

#slideh[][
  #figure(
    image("./images/bn.png", height: 70%),
    caption: [BTW try Binary Ninja #footnote[A very old comparison of IDA and Binary Ninja --- #link("https://github.com/saruman9/binja_vs_ida")[Binary Ninja 1.1.1184-dev vs IDA Pro 7.0.171130 (RU)]]
    ],
  )
]

#slideh[==== Signatures][
  - Ghidra: Function ID #footnote[#link("https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/FunctionID/src/main/help/help/topics/FunctionID/FunctionID.html")[FunctionID] help topic]
  - IDA Pro: lumen #footnote[https://github.com/naim94a/lumen] --- Lumina private server
  - Binary Ninja: Signature Libraries #footnote[https://binary.ninja/2020/03/11/signature-libraries.html]
]

#slideh[==== Diffing][
  - Version Tracking #footnote[#link("https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/VersionTracking/src/main/help/help/topics/VersionTrackingPlugin/Version_Tracking_Intro.html")[Version Tracking] help topic] in Ghidra
  - Program Differences #footnote[#link("https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/ProgramDiff/src/main/help/help/topics/Diff/Diff.htm")[Program Differences] help topic] in Ghidra
  - BinDiff #footnote[https://www.zynamics.com/bindiff.html]
  - Diaphora #footnote[https://github.com/joxeankoret/diaphora]
]

#slideh[=== Difficulties & Resolving][
  #only("1-2", [#emoji.quest])#only("3-", [#emoji.checkmark.box]) Java + C++

  #only(2, [#emoji.lightbulb Find "pure" functions])

  #only("-4", [#emoji.quest])#only("5-", [#emoji.checkmark.box]) Threads

  #only(4, [#emoji.lightbulb Find a target function in a call graph without threads])

  #only("-6", [#emoji.quest])#only("7-", [#emoji.checkmark.box]) Other shared libraries as dependencies

  #only(6, [#emoji.lightbulb To do patching of shared libraries])

  #only(6, [#emoji.lightbulb Load dependencies inside harness code])

  #only("-8", [#emoji.quest])#only("9-", [#emoji.checkmark.box]) Initialization in `JNI_OnLoad`

  #only(8, [#emoji.lightbulb Write stubs, call initialization functions])
]

#slideh[=== Example of a harness for the target function][
  #set text(.65em)
  #set align(center)
  ```c
  const ptrdiff_t ADDR_JNI_ONLOAD = 0x0000000000011640;
  const ptrdiff_t ADDR_PARSE_LINK = 0x000000000002F870;
  const ptrdiff_t ADDR_COPY_JNI_STRING_FROM_STR = 0x0000000000011160;
  [...]
  Functions *load_functions()
  {
    LIBC_SHARED = dlopen("/data/local/tmp/libc++_shared.so", RTLD_NOW | RTLD_GLOBAL);
    LIBICU_BINDER = dlopen("/data/local/tmp/libicuBinder.so", RTLD_NOW | RTLD_GLOBAL);
    LIBLINKPARSER = dlopen("/data/local/tmp/liblinkparser.so", RTLD_NOW | RTLD_GLOBAL);
    if (LIBLINKPARSER != NULL && LIBC_SHARED != NULL && LIBICU_BINDER != NULL)
    {
      int (*JNI_OnLoad)(void *, void *) = dlsym(LIBLINKPARSER, "JNI_OnLoad");
      void (*binder_init)() = dlsym(LIBICU_BINDER, "_ZN22IcuSqliteAndroidBinder4initEv");

      if (JNI_OnLoad != NULL && binder_init != NULL /* && binder_getInstance != NULL */)
      {
  [...]
  ```
]

#slideh[== Catches][
  - DoS
  - Leaks
  - Deadlocks
]

#slideh[== Sources (once again)][
  - Препарируем Viber. Мини-гид по анализу приложений для Android #footnote[https://xakep.ru/2023/05/16/analyzing-viber/] #sym.copyright _Хакер_
  - fuzzer + harness  #footnote[https://github.com/saruman9/viber_linkparser_fuzzer/]
]

#slideh[== Summary][
  - More details in the article #emoji.finger.t
  - The research has been interrupted, so go ahead!
  - The basic things for graybox fuzzing were considered, further --- more
]

#centered-slide[= WhatsApp
  #v(2em)
  #image(height: 50%, "./images/WhatsApp_logo-color-vertical.svg")
]

#slideh[== Static Analysis][
  - Manifest file --- #emoji.checkmark.box
  - Resources --- #emoji.checkmark.box, see the next slide
  - 1-day analysis + binary diffing --- #emoji.checkmark.box
]

#centered-slide[== Shared/Native Libraries]

#slideh[=== Superpack][
  Android app compression, which combines compiler analysis with data compression.

  See _Superpack: Pushing the limits of compression in Facebook’s mobile apps_ #footnote[https://engineering.fb.com/2021/09/13/core-data/superpack/] by Sapan Bhatia from Facebook.
]

#slideh[][
  Solutions:
  - Reverse engineering and developing
  - Reverse engineering and developing a wrapper (calling functions from a shared library in an emulator)
  - #only(2)[#set text(0.7em); #emoji.checkmark.box] Decompression in an emulator/Docker
]

#slideh[== Attack Vectors & Components][
  - Java part
  - Many open-source components
  - `libwhatsapp.so`
    - Statically linked
    - More and more Rust
]

#slideh[][
  After a long CFG/DFG analysis...

  - MP4 checking (incoming messages), converting (outgoing messages)
  - GIF checking
  - WEBP parsing (stickers)
  - `libmagi` (MIME type identification)
  - VoIP (PJSIP project #footnote[https://github.com/pjsip/pjproject])
]

#centered-slide[== Fuzzing]

#slideh[=== AFL++ + Frida][
  - Not as hard to build for Android as I expected #footnote[https://github.com/saruman9/AFLplusplus/tree/android]
  - Perfect for those who prefer C++
  - Not as flexible as LibAFL, but rich in functionality
]

#centered-slide[=== LibAFL + Frida]

#slideh[==== Android NDK + Frida + Rust = Building is the real pain!][
  Works: Rust 1.67, NDK 22, clang30

  Doesn't work:

  - Rust 1.67, NDK 25, clang\*
  - Rust 1.70, NDK 21, clang\*
  - Rust 1.70, NDK 22, clang\*
  - Rust 1.70, NDK 25, clang\*
]

#slideh[][
  + Moving Android toolchains from libgcc to libclang_rt #footnote[https://github.com/android/ndk/wiki/Changelog-r23#changes]
  + Updating the Android NDK in Rust 1.68 #footnote[https://blog.rust-lang.org/2023/01/09/android-ndk-update-r25.html]
  + Fixing build error for NDK 23 and above #footnote[https://github.com/rust-lang/rust/pull/85806#issuecomment-1096266946]
  + Patches for Frida (only for NDK below 23) #footnote[https://github.com/AFLplusplus/LibAFL/issues/1359#issuecomment-1693328137]
  + Workaround for aarch64 `__clear_cache` issue #footnote[https://github.com/AFLplusplus/LibAFL/issues/1359#issuecomment-1695346506]
  + A dirty hack for `frida-rust` #footnote[https://github.com/frida/frida-rust/pull/112]
]

#slideh[==== LibAFL problems][
  - DrCov coverage doesn't work as expected #footnote[https://github.com/AFLplusplus/LibAFL/pull/1579]#super[,] #footnote[https://github.com/AFLplusplus/LibAFL/pull/1581]
  - Asan doesn't work for Android x86_64 #footnote[https://github.com/AFLplusplus/LibAFL/pull/1578]
  - miniBSOD doesn't work for Android x86_64 #footnote[https://github.com/AFLplusplus/LibAFL/pull/1577]
]

#slideh[][
  - Additional changes#footnote[https://github.com/saruman9/LibAFL/branches/all]:
    - Option to continue fuzzing
    - Catching of timeout objectives
    - Option to disable coverage
    - The option of minimizing a corpus
]

#slideh[=== Frida][
  - I had a lot of problems because I didn't understand how Stalker works. Especially when analyzing complex objects (JIT is terrible)
  - Be sure to read the documentation #footnote[https://frida.re/docs/stalker/] for Stalker (and Gum interface) before using it #pause
  - LibAFL + Frida = Multithreading doesn't work
  - The sanitizer based on Frida doesn't work correctly on some arch/platforms
]

#slideh[=== Java VM][
  #set align(center)

  #text(2em)[#emoji.lightbulb]

  Harness = Java + Native Libraries

  But how? #pause

  Create Java VM from C/C++/Rust code of a harness/fuzzer!
]

#slideh[][
  Sources:

  - Creating a Java VM from Android Native Code #footnote[https://calebfenton.github.io/2017/04/05/creating_java_vm_from_android_native_code/] by Caleb Fenton
  - Calling JNI Functions with Java Object Arguments from the Command Line #footnote[https://calebfenton.github.io/2017/04/14/calling_jni_functions_with_java_object_arguments_from_the_command_line/] by Caleb Fenton
  - Loading Android ART virtual machine from native executables #footnote[https://gershnik.github.io/2021/03/26/load-art-from-native.html] by Eugene Gershnik
]

#slideh[==== Where hell begins?][
  #set align(center)

  #only(1)[Creating a Java VM is a non-trivial task!]
  #only(2)[#text(size: 1.2em)[Compliance with all legacy designs in Android is hard!]

    _I did a separate research on the ASOP source code_
  ]

  #only(3)[#text(size: 1.4em)[Running Java VM under a fuzzer and Frida is a pain!]

    _I spent many hours debugging_
  ]

  #only(4)[#text(size: 1.6em)[A real device and an emulator are two different things!]

    _I have used 3 real devices and countless versions of an emulator_
  ]

  #only(5)[#text(size: 2em)[It still doesn't work stably...]

    #text(size: 1.5em)[But it works! #footnote[https://github.com/saruman9/jnienv]#super[,]#footnote[BTW Valgrind for Android: https://github.com/saruman9/valgrind]]
  ]
]

#slideh[=== Smali patching][
  #only(1)[
    #set align(center)

    Does anyone know a tool that is comfortable to use for Smali patching?
  ]
  #only(2)[
    - Smali the Parseltongue Language #footnote[https://blog.quarkslab.com/smali-the-parseltongue-language.html] by Benoît Forgette from Quarkslab
    - Ghidra
    - Binary Ninja
    - Smalise extension for VSCode #footnote[https://github.com/LoyieKing/Smalise] by LoyieKing
  ]
]

#centered-slide[== Catches]

#slideh[=== DoS. Sender side][
  - Gallery
    - TIFF, SVG
    - OGG, WAV, MP3 
  - Live
    - Opus (audio recorder)
    - Video stream from a camera
  - Sending
    - MP4
]

#slideh[=== DoS. Receiver side][
  - Media hijacking
  - Android Java exceptions, native iOS crashes
]

#slideh[== Summary][
  - Only DoS... yet
  - VoIP is still waiting for me
]

#slideh[= General summary][
  - The journey is 1 year long #pause
  - From zero to #strike([hero]) some bugs with only fuzzing #pause
  - This is the vulnerability research for now, next time --- exploitation development
]

#[
  #set heading(outlined: false)
  #focus-slide[= Thank you!]
]
