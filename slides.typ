#import "@preview/polylux:0.3.1": *
#import themes.simple: *

#set text(font: ("Verdana"))
#let matrix_color = rgb("#008F11")
#show link: strong
#show link: set text(fill: blue)
#show: simple-theme.with()
#show raw.where(block: true): it => {
  if it.text.first() == "$" {
    block(
      fill: luma(200),
      inset: 10pt,
      radius: 4pt,
      it
    )
  } else {
    block(
      fill: luma(240),
      inset: 10pt,
      radius: 4pt,
      it
    )
  }
}
#show figure.caption: emph
#set figure(numbering: none)

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
    - I'm a user of the app --- #sym.checkmark
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
  - Bad BugBounty program
  - Good for a first research in this field
  - Many other methods of analysis can be applied
]

#centered-slide[= Viber
  #v(2em)
  #image(height: 50%, "./images/purple-icon_brand-center.png")
]

#slideh[== Sources][
  - #link("https://xakep.ru/2023/05/16/analyzing-viber/")[Препарируем Viber. Мини-гид по анализу приложений для Android] \@ Xakep
  - #link("https://github.com/saruman9/viber_linkparser_fuzzer/")[fuzzer + harness] \@ GitHub
]

#slideh[== Static Analysis][
  - Manifest file --- #sym.checkmark
  - Resources --- #sym.times
  - 1-day analysis + binary diffing --- #sym.checkmark
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
  - #link("https://github.com/skylot/jadx")[jadx] --- decompilation
  - IntelliJ IDEA --- deobfuscation, refactoring
  - #link("https://www.scitools.com/")[SciTools Understand] --- code-flow, data-flow analysis
  - `strings`, `grep`
]

#slideh[][
  #figure(
    caption: [Call graph of SVG native function in Understand],
    image("./images/understand.png", height: 80%)
  )
]

#slideh[=== Dynamic Analysis][
  - Frida and public scripts
  - `frida-trace`
  - Smali patching
  - Binary patching
]

#centered-slide[== Fuzzing]

#slideh[=== Blackbox is more interesting][
  - #only(1)[libFuzzer] #only("2-")[#strike[libFuzzer]]
  #only(3)[- honggfuzz] #only("4-")[- #strike[honggfuzz]]
  #only("5-")[- AFL++]
  #only("6-")[- LibAFL
  - etc.]
]

#slideh[][
  #set align(center)
  #table(columns: (auto, auto, auto, auto),
    align: (center, center, center),
    stroke: gray,
    inset: .3em,
    [*Fuzzer*], [*Instru\-mentation*], [*Emulator (x86_64)*], [*Real device, aarch64*],
    [AFL++ #footnote[#link("https://blog.quarkslab.com/android-greybox-fuzzing-with-afl-frida-mode.html")[Android greybox fuzzing with AFL++ Frida mode] by Eric Le Guevel from Quarkslab]], [Frida], [#sym.checkmark AFL++ in], [#sym.checkmark],
    [AFL++ #footnote[#link("https://alephsecurity.com/2021/11/16/fuzzing-qemu-android/")[AFL++ on Android with QEMU support] by Itai Greenhut (\@Gr33nh4t) from Aleph Research; #link("https://github.com/marcinguy/fpicker-aflpp-android")[fpicker-aflpp-android] by marcinguy]], [Qemu], [#sym.times], [#sym.checkmark],
    [AFL++ #footnote[#link("https://googleprojectzero.blogspot.com/2020/07/mms-exploit-part-2-effective-fuzzing-qmage.html")[MMS Exploit Part 2: Effective Fuzzing of the Qmage Codec] by Mateusz Jurczyk from Project Zero; #link("https://github.com/ant4g0nist/Sloth")[Sloth] by ant4g0nist]], [Qemu], [#sym.checkmark], [#sym.times],
    [AFL++], [Unicorn + qiling], [Unicorn], [#sym.times #sym.checkmark?],
    [honggfuzz/AFL++], [QBDI], [QBDI], [#sym.times #sym.checkmark?],
    [LibAFL], [Qemu], [#sym.times], [#sym.checkmark],
    [LibAFL], [Qemu], [#sym.checkmark], [#sym.times],
    [LibAFL], [Frida], [#sym.checkmark LibAFL in], [#sym.checkmark],
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
  - Ghidra
    - my #link("https://github.com/saruman9/ghidra")[Ghidra fork]
    - my #link("https://github.com/saruman9/ghidra_scripts")[ghidra_scripts]
    - #link("https://github.com/saruman9/recaster")[recaster plugin]
    - #link("https://github.com/saruman9/ghidra_dev_pres")[Ghidra. Dev. Presentation]
  - Binary Ninja --- my #link("https://github.com/saruman9/binja_snippets")[binja_snippets]
  - IDA Pro
  - rizin
]

#slideh[==== C++][
  Ghidra

  - `RecoverClassesFromRTTIScript.java`
  - `ApplyClassFunctionSignatureUpdatesScript.java`
  - `ApplyClassFunctionDefinitionUpdatesScript.java`
  - C++ directory in Script Manager
  - #link("https://github.com/astrelsky/Ghidra-Cpp-Class-Analyzer")[Ghidra-Cpp-Class-Analyzer] by astrelsky
]

#slideh[][
  IDA Pro

  - #link("https://github.com/Metadorius/ida_medigate")[ida_medigate] by Metadorius --- fork of fork of fork ...
  - #link("https://github.com/joeleong/ida-referee")[Referee] by joeleong --- a python port of James Koppel's Referee
]

#slideh[][
  Binary Ninja

  - Use development release channel
  - #link("https://github.com/CySHell/ClassyPP")[ClassyPP] by CySHell
  - #link("https://github.com/whitequark/binja_itanium_cxx_abi")[binja_itanium_cxx_abi] by whitequark

]

#slideh[][
  #figure(
    caption: [BTW try Binary Ninja #footnote[A very old comparison of IDA and Binary Ninja --- #link("https://github.com/saruman9/binja_vs_ida")[Binary Ninja 1.1.1184-dev vs IDA Pro 7.0.171130 (RU)]]],
    image("./images/bn.png", height: 70%)
  )
]

#slideh[==== Signatures][
  - Ghidra --- #link("https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/FunctionID/src/main/help/help/topics/FunctionID/FunctionID.html")[Function ID]
  - IDA Pro --- #link("https://github.com/naim94a/lumen")[lumen] --- Lumina private server
  - Binary Ninja --- #link("https://binary.ninja/2020/03/11/signature-libraries.html")[Signature Libraries]
]

#slideh[==== Diffing][
  - #link("https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/VersionTracking/src/main/help/help/topics/VersionTrackingPlugin/Version_Tracking_Intro.html")[Version Tracking] in Ghidra
  - #link("https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/ProgramDiff/src/main/help/help/topics/Diff/Diff.htm")[Program Differences] in Ghidra
  - #link("https://www.zynamics.com/bindiff.html")[BinDiff]
  - #link("https://github.com/joxeankoret/diaphora")[Diaphora]
]

#slideh[==== Binary Formats][
  - #link("https://core.telegram.org/mtproto")[MTProto]
  - VoIP Telegram
  - etc.

  See #link("https://github.com/saruman9/010_editor_templates")[010 Editor Templates].
]

#slideh[=== Difficulties][
  - Java + C++
  - Threads
  - Other shared libraries as dependencies
  - Initialization in `JNI_OnLoad`
]

#slideh[=== Resolving][
  - Find "pure" functions
  - Find a target function in a call graph without threads
  - To do patching of shared libraries
  - Load dependencies inside harness code
  - Write stubs, call initialization functions
]

#slideh[=== Example of a harness for the target function][
  #set text(.4em)
  ```c
  const ptrdiff_t ADDR_JNI_ONLOAD = 0x0000000000011640;
  const ptrdiff_t ADDR_PARSE_LINK = 0x000000000002F870;
  const ptrdiff_t ADDR_COPY_JNI_STRING_FROM_STR = 0x0000000000011160;
  [...]
  typedef struct ParserResult
  {
      struct String user_agent_string;
      struct String user_agent_info_string;
      struct String accept_string;
      struct String mime_type_string;
  } ParserResult;
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
        Dl_info jni_on_load_info;
        dladdr(JNI_OnLoad, &jni_on_load_info);
        size_t jni_on_load_addr = (size_t)jni_on_load_info.dli_saddr;

        Dl_info binder_init_info;
        dladdr(binder_init, &binder_init_info);
        size_t binder_init_addr = (size_t)binder_init_info.dli_saddr;

        int diff_parse_link = ADDR_PARSE_LINK - ADDR_JNI_ONLOAD;
        int diff_copy_jni_string_from_str = ADDR_COPY_JNI_STRING_FROM_STR - ADDR_JNI_ONLOAD;
        size_t parse_link_addr = jni_on_load_addr + diff_parse_link;
        size_t copy_jni_string_from_str_addr = jni_on_load_addr + diff_copy_jni_string_from_str;
        printf("[i] parse_link_addr: %zX\n", parse_link_addr);
        printf("[i] copy_jni_string_from_str_addr: %zX\n", copy_jni_string_from_str_addr);
        void (*parse_link)(ParserResult *, String *) = (void (*)(ParserResult *, String *))(parse_link_addr);
        void (*copy_jni_string_from_str)(String *, const char *) = (void (*)(String *, const char *))(copy_jni_string_from_str_addr);
        if (parse_link != NULL && copy_jni_string_from_str != NULL)
        {
          Functions *functions = (Functions *)malloc(sizeof(Functions));
          functions->parse_link = parse_link;
          functions->copy_jni_string_from_str = copy_jni_string_from_str;
          return functions;
	    }
  [...]
  ```
]

#slideh[== Sources (another time)][
  - #link("https://xakep.ru/2023/05/16/analyzing-viber/")[Препарируем Viber. Мини-гид по анализу приложений для Android] \@ Xakep
  - #link("https://github.com/saruman9/viber_linkparser_fuzzer/")[fuzzer + harness] \@ GitHub
]
