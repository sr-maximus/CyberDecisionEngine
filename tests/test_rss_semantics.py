from cyberdeck.collectors.rss import _detect_actor, _parse_rss


def test_generic_cyber_news_does_not_invent_attack_technique_or_actor():
    xml = """
    <rss><channel><item>
      <title>Security teams publish a defensive update</title>
      <description>General guidance without attributed adversary behavior.</description>
      <link>https://example.test/guidance</link>
    </item></channel></rss>
    """

    event = _parse_rss("Example", "https://example.test/feed", xml)[0]

    assert event.actor == "unattributed"
    assert event.technique is None
    assert event.technical_validation["classification"] == "contextual"
    assert event.technical_validation["summary"] == "General guidance without attributed adversary behavior."
    assert event.evidence_type.value == "news"


def test_actor_identifier_is_preserved_only_when_explicitly_present():
    assert _detect_actor("The report attributes this activity to UNC3944.") == "UNC3944"


def test_strategic_feed_is_context_not_an_observed_attack():
    xml = """
    <rss><channel><item>
      <title>New digital regulation changes investment requirements</title>
      <description>Policy and market context for technology companies.</description>
      <link>https://example.test/regulation</link>
    </item></channel></rss>
    """

    event = _parse_rss(
        "Strategic source",
        "https://example.test/feed",
        xml,
        metadata={"feed_type": "strategic", "context_topics": ["legal", "economic"]},
    )[0]

    assert event.category == "strategic_news"
    assert "strategic_context" in event.tags
    assert "context:legal" in event.tags
    assert event.technique is None
    assert event.technical_validation["classification"] == "contextual"
