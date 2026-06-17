import gleam/bool
import gleam/list
import gleam/option
import gleam/string
import licence_audit/error
import licence_audit/hex
import licence_audit/manifest
import licence_audit/osv

pub fn purl_for(entry: manifest.SbomEntry) -> Result(String, error.Error) {
  case entry.provenance {
    manifest.HexProvenance(_, _) ->
      Ok("pkg:hex/" <> string.lowercase(entry.name) <> "@" <> entry.version)
    manifest.GitProvenance(repo, commit) ->
      case parse_github_repo(repo) {
        Ok(#(owner, name)) ->
          Ok(
            "pkg:github/"
            <> string.lowercase(owner)
            <> "/"
            <> string.lowercase(name)
            <> "@"
            <> commit,
          )
        Error(_) ->
          Error(error.UnsupportedSourceForSbom(
            package: entry.name,
            source: "git",
            detail: "repo: " <> repo,
          ))
      }
    manifest.PathProvenance(path) ->
      Error(error.UnsupportedSourceForSbom(
        package: entry.name,
        source: "path",
        detail: "path: " <> path,
      ))
    manifest.UnknownProvenance(source) ->
      Error(error.UnsupportedSourceForSbom(
        package: entry.name,
        source: source,
        detail: "unsupported source",
      ))
  }
}

fn parse_github_repo(repo: String) -> Result(#(String, String), Nil) {
  use path <- result.try(github_repo_path(repo))
  case string.split(drop_suffix(drop_suffix(path, "/"), ".git"), on: "/") {
    [owner, name] if owner != "" && name != "" -> Ok(#(owner, name))
    _ -> Error(Nil)
  }
}

fn github_repo_path(repo: String) -> Result(String, Nil) {
  case strip_prefix(repo, "https://github.com/") {
    Ok(path) -> Ok(path)
    Error(_) ->
      case strip_prefix(repo, "http://github.com/") {
        Ok(path) -> Ok(path)
        Error(_) ->
          case strip_prefix(repo, "git@github.com:") {
            Ok(path) -> Ok(path)
            Error(_) -> strip_prefix(repo, "git@github.com/")
          }
      }
  }
}

fn strip_prefix(value: String, prefix: String) -> Result(String, Nil) {
  use <- bool.guard(
    when: !string.starts_with(value, prefix),
    return: Error(Nil),
  )
  Ok(string.drop_start(value, string.length(prefix)))
}

fn drop_suffix(value: String, suffix: String) -> String {
  use <- bool.guard(when: !string.ends_with(value, suffix), return: value)
  string.slice(value, 0, string.length(value) - string.length(suffix))
}

pub type LicenseEntry {
  LicenseId(id: String)
  LicenseName(name: String)
}

const spdx_ids = [
  "0BSD", "3D-Slicer-1.0", "AAL", "Abstyles", "AdaCore-doc", "Adobe-2006",
  "Adobe-Display-PostScript", "Adobe-Glyph", "Adobe-Utopia", "ADSL",
  "Advanced-Cryptics-Dictionary", "AFL-1.1", "AFL-1.2", "AFL-2.0", "AFL-2.1",
  "AFL-3.0", "Afmparse", "AGPL-1.0", "AGPL-1.0-only", "AGPL-1.0-or-later",
  "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later", "Aladdin",
  "ALGLIB-Documentation", "AMD-newlib", "AMDPLPA", "AML", "AML-glslang", "AMPAS",
  "ANTLR-PD", "ANTLR-PD-fallback", "any-OSI", "any-OSI-perl-modules",
  "Apache-1.0", "Apache-1.1", "Apache-2.0", "APAFML", "APL-1.0", "App-s2p",
  "APSL-1.0", "APSL-1.1", "APSL-1.2", "APSL-2.0", "Arphic-1999", "Artistic-1.0",
  "Artistic-1.0-cl8", "Artistic-1.0-Perl", "Artistic-2.0", "Artistic-dist",
  "Aspell-RU", "ASWF-Digital-Assets-1.0", "ASWF-Digital-Assets-1.1", "Baekmuk",
  "Bahyph", "Barr", "bcrypt-Solar-Designer", "Beerware", "Bitstream-Charter",
  "Bitstream-Vera", "BitTorrent-1.0", "BitTorrent-1.1", "blessing",
  "BlueOak-1.0.0", "Boehm-GC", "Boehm-GC-without-fee", "BOLA-1.1", "Borceux",
  "Brian-Gladman-2-Clause", "Brian-Gladman-3-Clause",
  "Brian-Gladman-3-Clause-no-conversion", "BSD-1-Clause", "BSD-2-Clause",
  "BSD-2-Clause-Darwin", "BSD-2-Clause-first-lines", "BSD-2-Clause-FreeBSD",
  "BSD-2-Clause-NetBSD", "BSD-2-Clause-Patent",
  "BSD-2-Clause-pkgconf-disclaimer", "BSD-2-Clause-Views", "BSD-3-Clause",
  "BSD-3-Clause-acpica", "BSD-3-Clause-Attribution", "BSD-3-Clause-Clear",
  "BSD-3-Clause-flex", "BSD-3-Clause-HP", "BSD-3-Clause-LBNL",
  "BSD-3-Clause-Modification", "BSD-3-Clause-No-Military-License",
  "BSD-3-Clause-No-Nuclear-License", "BSD-3-Clause-No-Nuclear-License-2014",
  "BSD-3-Clause-No-Nuclear-Warranty", "BSD-3-Clause-Open-MPI",
  "BSD-3-Clause-Sun", "BSD-3-Clause-Tso", "BSD-4-Clause",
  "BSD-4-Clause-Shortened", "BSD-4-Clause-UC", "BSD-4.3RENO", "BSD-4.3TAHOE",
  "BSD-Advertising-Acknowledgement", "BSD-Attribution-HPND-disclaimer",
  "BSD-Inferno-Nettverk", "BSD-Mark-Modifications", "BSD-Protection",
  "BSD-Source-beginning-file", "BSD-Source-Code", "BSD-Systemics",
  "BSD-Systemics-W3Works", "BSL-1.0", "Buddy", "BUSL-1.1", "bzip2-1.0.5",
  "bzip2-1.0.6", "C-UDA-1.0", "CAL-1.0", "CAL-1.0-Combined-Work-Exception",
  "Caldera", "Caldera-no-preamble", "CAPEC-tou", "Catharon", "CATOSL-1.1",
  "CC-BY-1.0", "CC-BY-2.0", "CC-BY-2.5", "CC-BY-2.5-AU", "CC-BY-3.0",
  "CC-BY-3.0-AT", "CC-BY-3.0-AU", "CC-BY-3.0-DE", "CC-BY-3.0-IGO",
  "CC-BY-3.0-NL", "CC-BY-3.0-US", "CC-BY-4.0", "CC-BY-NC-1.0", "CC-BY-NC-2.0",
  "CC-BY-NC-2.5", "CC-BY-NC-3.0", "CC-BY-NC-3.0-DE", "CC-BY-NC-4.0",
  "CC-BY-NC-ND-1.0", "CC-BY-NC-ND-2.0", "CC-BY-NC-ND-2.5", "CC-BY-NC-ND-3.0",
  "CC-BY-NC-ND-3.0-DE", "CC-BY-NC-ND-3.0-IGO", "CC-BY-NC-ND-4.0",
  "CC-BY-NC-SA-1.0", "CC-BY-NC-SA-2.0", "CC-BY-NC-SA-2.0-DE",
  "CC-BY-NC-SA-2.0-FR", "CC-BY-NC-SA-2.0-UK", "CC-BY-NC-SA-2.5",
  "CC-BY-NC-SA-3.0", "CC-BY-NC-SA-3.0-DE", "CC-BY-NC-SA-3.0-IGO",
  "CC-BY-NC-SA-4.0", "CC-BY-ND-1.0", "CC-BY-ND-2.0", "CC-BY-ND-2.5",
  "CC-BY-ND-3.0", "CC-BY-ND-3.0-DE", "CC-BY-ND-4.0", "CC-BY-SA-1.0",
  "CC-BY-SA-2.0", "CC-BY-SA-2.0-UK", "CC-BY-SA-2.1-JP", "CC-BY-SA-2.5",
  "CC-BY-SA-3.0", "CC-BY-SA-3.0-AT", "CC-BY-SA-3.0-DE", "CC-BY-SA-3.0-IGO",
  "CC-BY-SA-4.0", "CC-PDDC", "CC-PDM-1.0", "CC-SA-1.0", "CC0-1.0", "CDDL-1.0",
  "CDDL-1.1", "CDL-1.0", "CDLA-Permissive-1.0", "CDLA-Permissive-2.0",
  "CDLA-Sharing-1.0", "CECILL-1.0", "CECILL-1.1", "CECILL-2.0", "CECILL-2.1",
  "CECILL-B", "CECILL-C", "CERN-OHL-1.1", "CERN-OHL-1.2", "CERN-OHL-P-2.0",
  "CERN-OHL-S-2.0", "CERN-OHL-W-2.0", "CFITSIO", "check-cvs", "checkmk",
  "ClArtistic", "Clips", "CMU-Mach", "CMU-Mach-nodoc", "CNRI-Jython",
  "CNRI-Python", "CNRI-Python-GPL-Compatible", "COIL-1.0", "Community-Spec-1.0",
  "Condor-1.1", "copyleft-next-0.3.0", "copyleft-next-0.3.1",
  "Cornell-Lossless-JPEG", "CPAL-1.0", "CPL-1.0", "CPOL-1.02", "Cronyx",
  "Crossword", "CryptoSwift", "CrystalStacker", "CUA-OPL-1.0", "Cube", "curl",
  "cve-tou", "D-FSL-1.0", "DEC-3-Clause", "diffmark", "DL-DE-BY-2.0",
  "DL-DE-ZERO-2.0", "DOC", "DocBook-DTD", "DocBook-Schema", "DocBook-Stylesheet",
  "DocBook-XML", "Dotseqn", "DRL-1.0", "DRL-1.1", "DSDP", "dtoa", "dvipdfm",
  "ECL-1.0", "ECL-2.0", "eCos-2.0", "EFL-1.0", "EFL-2.0", "eGenix",
  "Elastic-2.0", "Entessa", "EPICS", "EPL-1.0", "EPL-2.0", "ErlPL-1.1",
  "ESA-PL-permissive-2.4", "ESA-PL-strong-copyleft-2.4",
  "ESA-PL-weak-copyleft-2.4", "etalab-2.0", "EUDatagrid", "EUPL-1.0", "EUPL-1.1",
  "EUPL-1.2", "Eurosym", "Fair", "FBM", "FDK-AAC", "Ferguson-Twofish",
  "Frameworx-1.0", "FreeBSD-DOC", "FreeImage", "FSFAP",
  "FSFAP-no-warranty-disclaimer", "FSFUL", "FSFULLR", "FSFULLRSD", "FSFULLRWD",
  "FSL-1.1-ALv2", "FSL-1.1-MIT", "FTL", "Furuseth", "fwlw",
  "Game-Programming-Gems", "GCR-docs", "GD", "generic-xts", "GFDL-1.1",
  "GFDL-1.1-invariants-only", "GFDL-1.1-invariants-or-later",
  "GFDL-1.1-no-invariants-only", "GFDL-1.1-no-invariants-or-later",
  "GFDL-1.1-only", "GFDL-1.1-or-later", "GFDL-1.2", "GFDL-1.2-invariants-only",
  "GFDL-1.2-invariants-or-later", "GFDL-1.2-no-invariants-only",
  "GFDL-1.2-no-invariants-or-later", "GFDL-1.2-only", "GFDL-1.2-or-later",
  "GFDL-1.3", "GFDL-1.3-invariants-only", "GFDL-1.3-invariants-or-later",
  "GFDL-1.3-no-invariants-only", "GFDL-1.3-no-invariants-or-later",
  "GFDL-1.3-only", "GFDL-1.3-or-later", "Giftware", "GL2PS", "Glide", "Glulxe",
  "GLWTPL", "gnuplot", "GPL-1.0", "GPL-1.0+", "GPL-1.0-only", "GPL-1.0-or-later",
  "GPL-2.0", "GPL-2.0+", "GPL-2.0-only", "GPL-2.0-or-later",
  "GPL-2.0-with-autoconf-exception", "GPL-2.0-with-bison-exception",
  "GPL-2.0-with-classpath-exception", "GPL-2.0-with-font-exception",
  "GPL-2.0-with-GCC-exception", "GPL-3.0", "GPL-3.0+", "GPL-3.0-only",
  "GPL-3.0-or-later", "GPL-3.0-with-autoconf-exception",
  "GPL-3.0-with-GCC-exception", "Graphics-Gems", "gSOAP-1.3b", "gtkbook",
  "Gutmann", "HaskellReport", "HDF5", "hdparm", "HIDAPI", "Hippocratic-2.1",
  "HP-1986", "HP-1989", "HPND", "HPND-DEC", "HPND-doc", "HPND-doc-sell",
  "HPND-export-US", "HPND-export-US-acknowledgement", "HPND-export-US-modify",
  "HPND-export2-US", "HPND-Fenneberg-Livingston", "HPND-INRIA-IMAG",
  "HPND-Intel", "HPND-Kevlin-Henney", "HPND-Markus-Kuhn",
  "HPND-merchantability-variant", "HPND-MIT-disclaimer", "HPND-Netrek",
  "HPND-Pbmplus", "HPND-sell-MIT-disclaimer-xserver", "HPND-sell-regexpr",
  "HPND-sell-variant", "HPND-sell-variant-critical-systems",
  "HPND-sell-variant-MIT-disclaimer", "HPND-sell-variant-MIT-disclaimer-rev",
  "HPND-SMC", "HPND-UC", "HPND-UC-export-US", "HTMLTIDY", "hyphen-bulgarian",
  "IBM-pibs", "ICU", "IEC-Code-Components-EULA", "IJG", "IJG-short",
  "ImageMagick", "iMatix", "Imlib2", "Info-ZIP", "Inner-Net-2.0", "InnoSetup",
  "Intel", "Intel-ACPI", "Interbase-1.0", "IPA", "IPL-1.0", "ISC",
  "ISC-Veillard", "ISO-permission", "Jam", "JasPer-2.0", "jove", "JPL-image",
  "JPNIC", "JSON", "Kastrup", "Kazlib", "Knuth-CTAN", "LAL-1.2", "LAL-1.3",
  "Latex2e", "Latex2e-translated-notice", "Leptonica", "LGPL-2.0", "LGPL-2.0+",
  "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1", "LGPL-2.1+", "LGPL-2.1-only",
  "LGPL-2.1-or-later", "LGPL-3.0", "LGPL-3.0+", "LGPL-3.0-only",
  "LGPL-3.0-or-later", "LGPLLR", "Libpng", "libpng-1.6.35", "libpng-2.0",
  "libselinux-1.0", "libtiff", "libutil-David-Nugent", "LiLiQ-P-1.1",
  "LiLiQ-R-1.1", "LiLiQ-Rplus-1.1", "Linux-man-pages-1-para",
  "Linux-man-pages-copyleft", "Linux-man-pages-copyleft-2-para",
  "Linux-man-pages-copyleft-var", "Linux-OpenIB", "LOOP", "LPD-document",
  "LPL-1.0", "LPL-1.02", "LPPL-1.0", "LPPL-1.1", "LPPL-1.2", "LPPL-1.3a",
  "LPPL-1.3c", "lsof", "Lucida-Bitmap-Fonts", "LZMA-SDK-9.11-to-9.20",
  "LZMA-SDK-9.22", "Mackerras-3-Clause", "Mackerras-3-Clause-acknowledgment",
  "magaz", "mailprio", "MakeIndex", "man2html", "Martin-Birgmeier",
  "McPhee-slideshow", "metamail", "Minpack", "MIPS", "MirOS", "MIT", "MIT-0",
  "MIT-advertising", "MIT-Click", "MIT-CMU", "MIT-enna", "MIT-feh",
  "MIT-Festival", "MIT-Khronos-old", "MIT-Modern-Variant", "MIT-open-group",
  "MIT-STK", "MIT-testregex", "MIT-Wu", "MITNFA", "MMIXware", "MMPL-1.0.1",
  "Motosoto", "MPEG-SSG", "mpi-permissive", "mpich2", "MPL-1.0", "MPL-1.1",
  "MPL-2.0", "MPL-2.0-no-copyleft-exception", "mplus", "MS-LPL", "MS-PL",
  "MS-RL", "MTLL", "MulanPSL-1.0", "MulanPSL-2.0", "Multics", "Mup", "MVT-1.1",
  "NAIST-2003", "NASA-1.3", "Naumen", "NBPL-1.0", "NCBI-PD", "NCGL-UK-2.0",
  "NCL", "NCSA", "Net-SNMP", "NetCDF", "Newsletr", "NGPL", "ngrep", "NICTA-1.0",
  "NIST-PD", "NIST-PD-fallback", "NIST-PD-TNT", "NIST-Software", "NLOD-1.0",
  "NLOD-2.0", "NLPL", "Nokia", "NOSL", "Noweb", "NPL-1.0", "NPL-1.1",
  "NPOSL-3.0", "NRL", "NTIA-PD", "NTP", "NTP-0", "Nunit", "O-UDA-1.0", "OAR",
  "OCCT-PL", "OCLC-2.0", "ODbL-1.0", "ODC-By-1.0", "OFFIS", "OFL-1.0",
  "OFL-1.0-no-RFN", "OFL-1.0-RFN", "OFL-1.1", "OFL-1.1-no-RFN", "OFL-1.1-RFN",
  "OGC-1.0", "OGDL-Taiwan-1.0", "OGL-Canada-2.0", "OGL-UK-1.0", "OGL-UK-2.0",
  "OGL-UK-3.0", "OGTSL", "OLDAP-1.1", "OLDAP-1.2", "OLDAP-1.3", "OLDAP-1.4",
  "OLDAP-2.0", "OLDAP-2.0.1", "OLDAP-2.1", "OLDAP-2.2", "OLDAP-2.2.1",
  "OLDAP-2.2.2", "OLDAP-2.3", "OLDAP-2.4", "OLDAP-2.5", "OLDAP-2.6", "OLDAP-2.7",
  "OLDAP-2.8", "OLFL-1.3", "OML", "OpenMDW-1.0", "OpenPBS-2.3", "OpenSSL",
  "OpenSSL-standalone", "OpenVision", "OPL-1.0", "OPL-UK-3.0", "OPUBL-1.0",
  "OSC-1.0", "OSET-PL-2.1", "OSL-1.0", "OSL-1.1", "OSL-2.0", "OSL-2.1",
  "OSL-3.0", "OSSP", "PADL", "ParaType-Free-Font-1.3", "Parity-6.0.0",
  "Parity-7.0.0", "PDDL-1.0", "PHP-3.0", "PHP-3.01", "Pixar", "pkgconf",
  "Plexus", "pnmstitch", "PolyForm-Noncommercial-1.0.0",
  "PolyForm-Small-Business-1.0.0", "PostgreSQL", "PPL", "PSF-2.0", "psfrag",
  "psutils", "Python-2.0", "Python-2.0.1", "python-ldap", "Qhull", "QPL-1.0",
  "QPL-1.0-INRIA-2004", "radvd", "Rdisc", "RHeCos-1.1", "RPL-1.1", "RPL-1.5",
  "RPSL-1.0", "RSA-MD", "RSCPL", "Ruby", "Ruby-pty", "SAX-PD", "SAX-PD-2.0",
  "Saxpath", "SCEA", "SchemeReport", "Sendmail", "Sendmail-8.23",
  "Sendmail-Open-Source-1.1", "SGI-B-1.0", "SGI-B-1.1", "SGI-B-2.0",
  "SGI-OpenGL", "SGMLUG-PM", "SGP4", "SHL-0.5", "SHL-0.51", "SimPL-2.0", "SISSL",
  "SISSL-1.2", "SL", "Sleepycat", "SMAIL-GPL", "SMLNJ", "SMPPL", "SNIA",
  "snprintf", "SOFA", "softSurfer", "Soundex", "Spencer-86", "Spencer-94",
  "Spencer-99", "SPL-1.0", "ssh-keyscan", "SSH-OpenSSH", "SSH-short",
  "SSLeay-standalone", "SSPL-1.0", "StandardML-NJ", "SugarCRM-1.1.3", "SUL-1.0",
  "Sun-PPP", "Sun-PPP-2000", "SunPro", "SWL", "swrule", "Symlinks",
  "TAPR-OHL-1.0", "TCL", "TCP-wrappers", "TekHVC", "TermReadKey", "TGPPL-1.0",
  "ThirdEye", "threeparttable", "TMate", "TORQUE-1.1", "TOSL", "TPDL", "TPL-1.0",
  "TrustedQSL", "TTWL", "TTYP0", "TU-Berlin-1.0", "TU-Berlin-2.0",
  "Ubuntu-font-1.0", "UCAR", "UCL-1.0", "ulem", "UMich-Merit", "Unicode-3.0",
  "Unicode-DFS-2015", "Unicode-DFS-2016", "Unicode-TOU", "UnixCrypt",
  "Unlicense", "Unlicense-libtelnet", "Unlicense-libwhirlpool", "UnRAR",
  "UPL-1.0", "URT-RLE", "Vim", "Vixie-Cron", "VOSTROM", "VSL-1.0", "W3C",
  "W3C-19980720", "W3C-20150513", "w3m", "Watcom-1.0", "Widget-Workshop",
  "WordNet", "Wsuipa", "WTFNMFPL", "WTFPL", "wwl", "wxWindows", "X11",
  "X11-distribute-modifications-variant", "X11-no-permit-persons", "X11-swapped",
  "Xdebug-1.03", "Xerox", "Xfig", "XFree86-1.1", "xinetd",
  "xkeyboard-config-Zinoviev", "xlock", "Xnet", "xpp", "XSkat", "xzoom",
  "YPL-1.0", "YPL-1.1", "Zed", "Zeeff", "Zend-2.0", "Zimbra-1.3", "Zimbra-1.4",
  "Zlib", "zlib-acknowledgement", "ZPL-1.1", "ZPL-2.0", "ZPL-2.1",
]

const spdx_ids_outside_cyclonedx_16 = [
  "Brian-Gladman-3-Clause-no-conversion", "MVT-1.1",
]

/// Map raw declared licence strings to CycloneDX licence entries, one per
/// declared licence. When a package declares more than one, they are emitted as
/// separate entries: Hex does not record whether the relationship is
/// conjunctive ("AND") or disjunctive ("OR"), so we do not synthesise an SPDX
/// expression that would assert an operator we cannot verify.
pub fn license_entries(licences: List(String)) -> List(LicenseEntry) {
  licences
  |> list.map(fn(raw) {
    case match_spdx(raw) {
      Ok(canonical) -> LicenseId(canonical)
      Error(_) -> LicenseName(raw)
    }
  })
  |> dedupe_license_entries
}

fn dedupe_license_entries(entries: List(LicenseEntry)) -> List(LicenseEntry) {
  entries
  |> list.fold([], fn(acc, entry) {
    case list.contains(acc, entry) {
      True -> acc
      False -> [entry, ..acc]
    }
  })
  |> list.reverse
}

fn match_spdx(raw: String) -> Result(String, Nil) {
  let lower = string.lowercase(raw)
  case
    list.find(spdx_ids_outside_cyclonedx_16, fn(id) {
      string.lowercase(id) == lower
    })
  {
    Ok(_) -> Error(Nil)
    Error(_) -> list.find(spdx_ids, fn(id) { string.lowercase(id) == lower })
  }
}

import gleam/dict.{type Dict}
import gleam/json
import gleam/result
import licence_audit/sbom_uuid

pub type RootComponent {
  RootComponent(
    name: String,
    version: String,
    /// Project summary from the root `gleam.toml` `description`, if any.
    description: option.Option(String),
    /// Declared licences from the root `gleam.toml` `licences` array.
    licences: List(String),
    /// Project source URL (e.g. derived from a `repository` github table).
    repository: option.Option(String),
  )
}

/// How the BOM `serialNumber` is produced.
pub type SerialNumber {
  /// Use this exact `urn:uuid` string (a random v4 in normal runs).
  FixedSerial(String)
  /// Derive a deterministic `urn:uuid` from a hash of the BOM content, so the
  /// same dependency set always yields the same serial number.
  ContentDerivedSerial
}

/// An OSV advisory paired with the component `bom-ref`s (purls) it affects,
/// ready to be emitted into the CycloneDX `vulnerabilities` array. An empty
/// list of these on `SbomInput` omits the array entirely.
pub type EmbeddedVulnerability {
  EmbeddedVulnerability(vuln: osv.Vulnerability, affects: List(String))
}

pub type SbomInput {
  SbomInput(
    manifest: manifest.SbomManifest,
    root: RootComponent,
    tool_version: String,
    serial_number: SerialNumber,
    timestamp: String,
    package_metadata: Dict(String, hex.PackageMetadata),
    scopes: Dict(String, manifest.Scope),
    /// Vulnerabilities to embed (CycloneDX `vulnerabilities`); empty omits it.
    vulnerabilities: List(EmbeddedVulnerability),
  )
}

/// Returns the rendered JSON, or an `Error` if any entry has an unsupported
/// source for purl generation.
pub fn try_render(input: SbomInput) -> Result(String, error.Error) {
  // Emit components and dependencies in a stable, content-defined order so the
  // output is canonical regardless of how the manifest happened to be ordered.
  let sorted_entries =
    list.sort(input.manifest.entries, by: fn(a, b) {
      string.compare(sort_key(a), sort_key(b))
    })
  let sorted_manifest =
    manifest.SbomManifest(..input.manifest, entries: sorted_entries)
  use components <- result.try(
    list.try_map(sorted_entries, fn(entry) {
      build_component(entry, input.package_metadata, input.scopes)
    }),
  )
  let dependencies = build_dependencies(sorted_manifest)
  let vulnerabilities = build_vulnerabilities(input.vulnerabilities)
  let serial = resolve_serial(input, components, dependencies, vulnerabilities)
  let document =
    build_document(input, serial, components, dependencies, vulnerabilities)
  Ok(json.to_string(document))
}

/// Sort key for a component: its purl when available, falling back to the
/// package name for sources without one.
fn sort_key(entry: manifest.SbomEntry) -> String {
  case purl_for(entry) {
    Ok(purl) -> purl
    Error(_) -> entry.name
  }
}

/// Resolve the BOM `serialNumber`: either the caller-supplied fixed value, or a
/// deterministic UUID derived from a hash of the rendered components and
/// dependencies plus the described project.
fn resolve_serial(
  input: SbomInput,
  components: List(json.Json),
  dependencies: List(json.Json),
  vulnerabilities: List(json.Json),
) -> String {
  case input.serial_number {
    FixedSerial(value) -> value
    ContentDerivedSerial -> {
      let content =
        json.to_string(json.preprocessed_array(components))
        <> json.to_string(json.preprocessed_array(dependencies))
        <> json.to_string(json.preprocessed_array(vulnerabilities))
        <> json.to_string(root_component_json(input.root))
        <> input.tool_version
      sbom_uuid.serial_number_from_content(content)
    }
  }
}

/// Convenience wrapper that panics on unsupported-source errors. Used in
/// tests with pre-validated input.
pub fn render(input: SbomInput) -> String {
  let assert Ok(rendered) = try_render(input)
  rendered
}

fn build_component(
  entry: manifest.SbomEntry,
  package_metadata: Dict(String, hex.PackageMetadata),
  scopes: Dict(String, manifest.Scope),
) -> Result(json.Json, error.Error) {
  use purl <- result.try(purl_for(entry))
  let metadata = dict.get(package_metadata, entry.name)

  let fields =
    [
      #("bom-ref", json.string(purl)),
      #("type", json.string("library")),
      #("name", json.string(entry.name)),
      #("purl", json.string(purl)),
    ]
    |> append_version(entry.version)
    |> append_supplier(entry, metadata)
    |> append_publisher(metadata)
    |> append_description(metadata)
    |> append_hashes(entry)
    |> append_licenses(metadata)
    |> append_external_references(entry, metadata)
    |> append_properties(entry, scopes)

  Ok(json.object(fields))
}

type Field =
  #(String, json.Json)

fn append_version(fields: List(Field), version: String) -> List(Field) {
  case version {
    "" -> fields
    _ -> list.append(fields, [#("version", json.string(version))])
  }
}

fn append_description(
  fields: List(Field),
  metadata: Result(hex.PackageMetadata, Nil),
) -> List(Field) {
  case metadata {
    Ok(hex.PackageMetadata(description: option.Some(description), ..)) ->
      list.append(fields, [#("description", json.string(description))])
    _ -> fields
  }
}

/// CycloneDX `supplier` is the organisation that supplied the component. For
/// Hex packages that is always the Hex registry, so we emit a uniform
/// `{name: "Hex", url: ["https://hex.pm/packages/<name>"]}` object per Hex
/// component. Package owners/maintainers are surfaced separately via
/// `publisher`, so the two fields stay semantically distinct: supplier = where
/// the artefact came from, publisher = who authored/released it.
fn append_supplier(
  fields: List(Field),
  entry: manifest.SbomEntry,
  _metadata: Result(hex.PackageMetadata, Nil),
) -> List(Field) {
  case entry.provenance {
    manifest.HexProvenance(_, _) ->
      list.append(fields, [
        #(
          "supplier",
          json.object([
            #("name", json.string("Hex")),
            #(
              "url",
              json.preprocessed_array([
                json.string("https://hex.pm/packages/" <> entry.name),
              ]),
            ),
          ]),
        ),
      ])
    _ -> fields
  }
}

/// CycloneDX `publisher` is a single string identifying the person or
/// organisation that published the component. We populate it from Hex
/// `owners` (preferred) or `meta.maintainers`; see `hex.publisher_from_names`.
fn append_publisher(
  fields: List(Field),
  metadata: Result(hex.PackageMetadata, Nil),
) -> List(Field) {
  case metadata {
    Ok(hex.PackageMetadata(publisher: option.Some(publisher), ..)) ->
      list.append(fields, [#("publisher", json.string(publisher))])
    _ -> fields
  }
}

fn append_hashes(
  fields: List(Field),
  entry: manifest.SbomEntry,
) -> List(Field) {
  case entry.provenance {
    manifest.HexProvenance(checksum, _) ->
      list.append(fields, [
        #(
          "hashes",
          json.preprocessed_array([
            json.object([
              #("alg", json.string("SHA-256")),
              #("content", json.string(string.lowercase(checksum))),
            ]),
          ]),
        ),
      ])
    _ -> fields
  }
}

fn append_licenses(
  fields: List(Field),
  metadata: Result(hex.PackageMetadata, Nil),
) -> List(Field) {
  case metadata {
    Ok(meta) ->
      case license_entries(meta.licences) {
        [] -> fields
        entries ->
          list.append(fields, [
            #(
              "licenses",
              json.preprocessed_array(list.map(entries, license_to_json)),
            ),
          ])
      }
    Error(_) -> fields
  }
}

fn append_external_references(
  fields: List(Field),
  entry: manifest.SbomEntry,
  metadata: Result(hex.PackageMetadata, Nil),
) -> List(Field) {
  let links = case metadata {
    Ok(meta) -> meta.links
    Error(_) -> []
  }
  case external_references(entry, links) {
    [] -> fields
    refs ->
      list.append(fields, [
        #("externalReferences", json.preprocessed_array(refs)),
      ])
  }
}

fn append_properties(
  fields: List(Field),
  entry: manifest.SbomEntry,
  scopes: Dict(String, manifest.Scope),
) -> List(Field) {
  let scope = case dict.get(scopes, entry.name) {
    Ok(scope) -> scope
    Error(_) -> manifest.Prod
  }
  let scope_property =
    json.object([
      #("name", json.string("licence_audit:scope")),
      #("value", json.string(manifest.scope_label(scope))),
    ])
  // CycloneDX `hashes` cannot distinguish two SHA-256 entries (the schema
  // only allows `alg`/`content`), so the Hex inner checksum is surfaced as a
  // labelled property when present. The outer checksum stays in `hashes`
  // because that is the canonical artefact hash consumers verify against.
  let properties = case entry.provenance {
    manifest.HexProvenance(_, option.Some(inner)) -> [
      scope_property,
      json.object([
        #("name", json.string("licence_audit:hex_inner_checksum")),
        #("value", json.string(string.lowercase(inner))),
      ]),
    ]
    _ -> [scope_property]
  }
  list.append(fields, [#("properties", json.preprocessed_array(properties))])
}

/// Build CycloneDX `externalReferences` for a component: the Hex tarball as a
/// `distribution` reference (Hex packages only), followed by each Hex
/// `meta.links` entry mapped to a reference type. The original link label is
/// preserved as the reference `comment`.
fn external_references(
  entry: manifest.SbomEntry,
  links: List(#(String, String)),
) -> List(json.Json) {
  let from_links =
    list.map(links, fn(pair) {
      json.object([
        #("url", json.string(pair.1)),
        #("type", json.string(reference_type(pair.0))),
        #("comment", json.string(pair.0)),
      ])
    })
  case entry.provenance {
    manifest.HexProvenance(_, _) -> [
      hex_distribution_reference(entry),
      ..from_links
    ]
    _ -> from_links
  }
}

fn hex_distribution_reference(entry: manifest.SbomEntry) -> json.Json {
  json.object([
    #(
      "url",
      json.string(
        "https://repo.hex.pm/tarballs/"
        <> entry.name
        <> "-"
        <> entry.version
        <> ".tar",
      ),
    ),
    #("type", json.string("distribution")),
    #("comment", json.string("Hex package tarball")),
  ])
}

/// Map a Hex link label to a CycloneDX external-reference type. Unknown labels
/// fall back to `other` so no link is dropped.
fn reference_type(label: String) -> String {
  case string.lowercase(label) {
    "github"
    | "gitlab"
    | "bitbucket"
    | "source"
    | "repository"
    | "repo"
    | "vcs" -> "vcs"
    "website" | "homepage" | "home" -> "website"
    "docs" | "documentation" | "hexdocs" -> "documentation"
    _ -> "other"
  }
}

fn license_to_json(entry: LicenseEntry) -> json.Json {
  // `acknowledgement: declared` (CycloneDX 1.6) records that these licences are
  // as declared by the package's own metadata (Hex / gleam.toml), not concluded
  // by scanning the source.
  let fields = case entry {
    LicenseId(id) -> [#("id", json.string(id))]
    LicenseName(name) -> [#("name", json.string(name))]
  }
  json.object([
    #(
      "license",
      json.object(
        list.append(fields, [
          #("acknowledgement", json.string("declared")),
        ]),
      ),
    ),
  ])
}

fn build_dependencies(
  manifest_value: manifest.SbomManifest,
) -> List(json.Json) {
  let purl_index =
    list.fold(manifest_value.entries, dict.new(), fn(acc, entry) {
      case purl_for(entry) {
        Ok(purl) -> dict.insert(acc, entry.name, purl)
        Error(_) -> acc
      }
    })
  let root_entry =
    component_refs(
      "root",
      resolve_purls(manifest_value.root_requirements, purl_index),
    )
  let other_entries =
    list.filter_map(manifest_value.entries, fn(entry) {
      component_entry(entry, purl_index)
    })
  [root_entry, ..other_entries]
}

/// Map dependency names to their purls, dropping any not present in the index.
fn resolve_purls(
  names: List(String),
  purl_index: Dict(String, String),
) -> List(String) {
  list.filter_map(names, fn(name) { dict.get(purl_index, name) })
}

/// Build the `dependencies` entry for a single component, or `Error(Nil)` if
/// the entry has no purl (e.g. a non-Hex package).
fn component_entry(
  entry: manifest.SbomEntry,
  purl_index: Dict(String, String),
) -> Result(json.Json, Nil) {
  case purl_for(entry) {
    Error(_) -> Error(Nil)
    Ok(self_purl) ->
      Ok(component_refs(
        self_purl,
        resolve_purls(entry.requirements, purl_index),
      ))
  }
}

fn component_refs(ref: String, deps: List(String)) -> json.Json {
  json.object([
    #("ref", json.string(ref)),
    #("dependsOn", json.array(list.sort(deps, string.compare), of: json.string)),
  ])
}

const bom_vendor = "tylerbutler"

/// Build the `metadata.component` object for the project being described,
/// enriching the bare name/version with whatever `gleam.toml` provided.
fn root_component_json(root: RootComponent) -> json.Json {
  [
    #("bom-ref", json.string("root")),
    #("type", json.string("application")),
    #("name", json.string(root.name)),
    #("version", json.string(root.version)),
  ]
  |> fn(fields) {
    case root_purl(root) {
      option.Some(purl) ->
        list.append(fields, [
          #("purl", json.string(purl)),
        ])
      option.None -> fields
    }
  }
  |> fn(fields) {
    case root.description {
      option.Some(description) ->
        list.append(fields, [#("description", json.string(description))])
      option.None -> fields
    }
  }
  |> fn(fields) {
    case license_entries(root.licences) {
      [] -> fields
      entries ->
        list.append(fields, [
          #(
            "licenses",
            json.preprocessed_array(list.map(entries, license_to_json)),
          ),
        ])
    }
  }
  |> fn(fields) {
    case root.repository {
      option.Some(url) ->
        list.append(fields, [
          #(
            "externalReferences",
            json.preprocessed_array([
              json.object([
                #("url", json.string(url)),
                #("type", json.string("vcs")),
              ]),
            ]),
          ),
        ])
      option.None -> fields
    }
  }
  |> json.object
}

fn root_purl(root: RootComponent) -> option.Option(String) {
  case root.repository {
    option.Some(repo) ->
      case parse_github_repo(repo) {
        Ok(#(owner, name)) ->
          option.Some(
            "pkg:github/"
            <> string.lowercase(owner)
            <> "/"
            <> string.lowercase(name),
          )
        Error(_) -> option.None
      }
    option.None -> option.None
  }
}

fn build_document(
  input: SbomInput,
  serial: String,
  components: List(json.Json),
  dependencies: List(json.Json),
  vulnerabilities: List(json.Json),
) -> json.Json {
  let base = [
    #(
      "$schema",
      json.string("https://cyclonedx.org/schema/bom-1.6.schema.json"),
    ),
    #("bomFormat", json.string("CycloneDX")),
    #("specVersion", json.string("1.6")),
    #("serialNumber", json.string(serial)),
    #("version", json.int(1)),
    #(
      "metadata",
      json.object([
        #("timestamp", json.string(input.timestamp)),
        // SBOMs are produced from the locked manifest, i.e. the dependency set
        // used to build the project.
        #(
          "lifecycles",
          json.preprocessed_array([
            json.object([#("phase", json.string("build"))]),
          ]),
        ),
        #(
          "tools",
          json.preprocessed_array([
            json.object([
              #("vendor", json.string(bom_vendor)),
              #("name", json.string("licence_audit")),
              #("version", json.string(input.tool_version)),
            ]),
          ]),
        ),
        // The BOM is authored by the licence_audit maintainer, independent of
        // whichever project it describes.
        #(
          "authors",
          json.preprocessed_array([
            json.object([#("name", json.string(bom_vendor))]),
          ]),
        ),
        #("component", root_component_json(input.root)),
      ]),
    ),
    #("components", json.preprocessed_array(components)),
    #("dependencies", json.preprocessed_array(dependencies)),
    // The locked manifest is the fully resolved dependency tree, so the graph
    // rooted at `root` is complete rather than partial.
    #(
      "compositions",
      json.preprocessed_array([
        json.object([
          #("aggregate", json.string("complete")),
          #("dependencies", json.preprocessed_array([json.string("root")])),
        ]),
      ]),
    ),
  ]
  // Only emit `vulnerabilities` when vulnerabilities were embedded, so a plain
  // SBOM keeps its existing shape.
  let fields = case vulnerabilities {
    [] -> base
    _ ->
      list.append(base, [
        #("vulnerabilities", json.preprocessed_array(vulnerabilities)),
      ])
  }
  json.object(fields)
}

/// Map each embedded advisory to a CycloneDX `vulnerabilities[]` entry,
/// emitted in a stable order by advisory id for canonical output.
fn build_vulnerabilities(
  vulnerabilities: List(EmbeddedVulnerability),
) -> List(json.Json) {
  vulnerabilities
  |> list.sort(by: fn(a, b) { string.compare(a.vuln.id, b.vuln.id) })
  |> list.map(vulnerability_json)
}

fn vulnerability_json(embedded: EmbeddedVulnerability) -> json.Json {
  let vuln = embedded.vuln
  let source =
    json.object([
      #("name", json.string("OSV")),
      #("url", json.string("https://osv.dev/vulnerability/" <> vuln.id)),
    ])
  let base = [
    #("bom-ref", json.string("vuln:" <> vuln.id)),
    #("id", json.string(vuln.id)),
    #("source", source),
    #("ratings", json.preprocessed_array(ratings_json(vuln))),
  ]
  let with_description = case vuln.summary {
    "" -> base
    summary -> list.append(base, [#("description", json.string(summary))])
  }
  let affects =
    embedded.affects
    |> list.sort(string.compare)
    |> list.map(fn(ref) { json.object([#("ref", json.string(ref))]) })
  json.object(
    list.append(with_description, [
      #("affects", json.preprocessed_array(affects)),
    ]),
  )
}

/// CycloneDX `ratings` for an advisory: one entry per CVSS vector reported by
/// OSV (with `method` + `vector`), or a single severity-only entry when OSV
/// gave no machine-readable vector. The advisory's resolved severity bucket is
/// used as the `severity` in all cases, since OSV's `database_specific` label
/// (when present) is authoritative.
fn ratings_json(vuln: osv.Vulnerability) -> List(json.Json) {
  let severity = json.string(osv.severity_to_string(vuln.severity))
  let osv_source = json.object([#("name", json.string("OSV"))])
  case vuln.scores {
    [] -> [json.object([#("source", osv_source), #("severity", severity)])]
    scores ->
      list.map(scores, fn(score) {
        json.object([
          #("source", osv_source),
          #("method", json.string(cvss_method(score.kind, score.vector))),
          #("vector", json.string(score.vector)),
          #("severity", severity),
        ])
      })
  }
}

/// Map an OSV CVSS score to a CycloneDX `ratings.method` enum value. The vector
/// string's version prefix is authoritative when present (CVSS v2 vectors carry
/// no prefix); otherwise we fall back to the OSV score `type`.
fn cvss_method(kind: String, vector: String) -> String {
  let upper = string.uppercase(vector)
  case
    string.contains(upper, "CVSS:3.1"),
    string.contains(upper, "CVSS:3.0"),
    string.contains(upper, "CVSS:4.0")
  {
    True, _, _ -> "CVSSv31"
    _, True, _ -> "CVSSv3"
    _, _, True -> "CVSSv4"
    _, _, _ ->
      case string.uppercase(kind) {
        "CVSS_V4" -> "CVSSv4"
        "CVSS_V3" -> "CVSSv3"
        "CVSS_V2" -> "CVSSv2"
        _ -> "other"
      }
  }
}
