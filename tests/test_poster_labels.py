"""Reject labels the bundled poster fonts cannot draw, including old aliases."""

import pytest

from logscan_web.poster_labels import poster_label_supported


@pytest.mark.parametrize("name", ["Kosuke Suzuki", "Mio Sakura", "Zoë García", "Hikaru Kondô", "50 Cent", "Person (123)", "Zoe\u0308 Garci\u0301a"])
def test_supported_labels_preserve_english_and_accented_names(name):
    assert poster_label_supported(name)


@pytest.mark.parametrize("name", ["吴 梦梦", "宋雨川", "梁佳芯", "温芮欣", "박지", "桜みお", "铃木浩介", "Catherine Lagaʻaia", "Lương Bích Hữu", "Ronkẹ Adékoluẹjo", "Văn Phượng"])
def test_labels_missing_glyphs_in_any_used_font_are_blocked(name):
    assert not poster_label_supported(name)


@pytest.mark.parametrize("name", ["", "   ", "123", "Person|Other", "Person\nOther", "Person\rOther", "Person\x00", None])
def test_empty_or_unsafe_export_labels_are_blocked(name):
    assert not poster_label_supported(name)
