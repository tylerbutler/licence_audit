import gleeunit/should
import licence_audit/emoji

pub fn mit_maps_to_graduation_cap_test() {
  should.equal(emoji.for_licence("MIT"), "🎓")
}

pub fn apache_maps_to_feather_test() {
  should.equal(emoji.for_licence("Apache-2.0"), "🪶")
}

pub fn bsd_maps_to_tree_test() {
  should.equal(emoji.for_licence("BSD-3-Clause"), "🌲")
}

pub fn zero_bsd_maps_to_free_test() {
  should.equal(emoji.for_licence("0BSD"), "🆓")
}

pub fn gpl_maps_to_gnu_test() {
  should.equal(emoji.for_licence("GPL-3.0"), "🐃")
}

pub fn lgpl_does_not_match_gpl_test() {
  should.equal(emoji.for_licence("LGPL-2.1"), "📚")
}

pub fn agpl_does_not_match_gpl_test() {
  should.equal(emoji.for_licence("AGPL-3.0"), "🌐")
}

pub fn mpl_maps_to_lizard_test() {
  should.equal(emoji.for_licence("MPL-2.0"), "🦎")
}

pub fn case_is_ignored_test() {
  should.equal(emoji.for_licence("mit"), "🎓")
  should.equal(emoji.for_licence("apache-2.0"), "🪶")
}

pub fn unknown_licence_falls_back_to_question_test() {
  should.equal(emoji.for_licence("Something-Weird"), "❔")
}

pub fn for_licences_joins_emojis_test() {
  should.equal(emoji.for_licences(["MIT", "Apache-2.0"]), "🎓 🪶")
}

pub fn for_licences_empty_returns_fallback_test() {
  should.equal(emoji.for_licences([]), "❔")
}
