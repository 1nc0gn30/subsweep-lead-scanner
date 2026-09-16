"""Unit tests for subsweep_lead_scanner.lead_extractor module."""

import json
import pytest
from subsweep_lead_scanner.lead_extractor import (
    AddressData,
    BusinessEntity,
    GeoCoordinates,
    LeadData,
    LeadExtractor,
    RatingData,
)


@pytest.fixture
def extractor() -> LeadExtractor:
    """Instantiate LeadExtractor instance."""
    return LeadExtractor()


class TestEmailHarvesting:
    """Test email extraction, cleaning, and false positive rejection."""

    def test_extract_standard_emails(self, extractor):
        """Harvest standard emails from raw HTML text."""
        html = """
        <p>Contact us at <a href="mailto:support@acme-corp.com">support@acme-corp.com</a></p>
        <p>For sales inquiries, email sales.lead+enterprise@acme-corp.co.uk</p>
        """
        emails = extractor.extract_emails(html)
        assert "support@acme-corp.com" in emails
        assert "sales.lead+enterprise@acme-corp.co.uk" in emails

    def test_extract_obfuscated_emails(self, extractor):
        """De-obfuscate [at] and (at) protected emails."""
        html = "<p>Reach out: founder [at] myrocket.ai or security (at) myrocket [dot] ai</p>"
        emails = extractor.extract_emails(html)
        assert "founder@myrocket.ai" in emails
        assert "security@myrocket.ai" in emails

    def test_filter_false_positives(self, extractor):
        """Reject image assets, fonts, and dummy placeholder emails."""
        html = """
        <img src="logo@2x.png" />
        <link href="fonts@v1.woff2" />
        <p>Example: user@example.com or test@test.com or placeholder@sentry.io</p>
        """
        emails = extractor.extract_emails(html)
        assert len(emails) == 0


class TestPhoneHarvesting:
    """Test international and national phone extraction."""

    def test_extract_us_and_international_phones(self, extractor):
        """Harvest US formatted and international phone numbers."""
        html = """
        <div>
            Call our headquarters: <span>(415) 555-0199</span>
            UK Branch: <span>+44 20 7946 0958</span>
            <a href="tel:+18005550144">Toll-Free Direct</a>
        </div>
        """
        phones = extractor.extract_phones(html)
        assert "(415) 555-0199" in phones or "+18005550144" in phones
        assert any("555" in p for p in phones)
        assert any("+44" in p for p in phones) or any("0958" in p for p in phones)


class TestSocialProfiles:
    """Test social media profile URL harvesting."""

    def test_extract_social_links(self, extractor):
        """Extract brand social media profile links while filtering share widgets."""
        html = """
        <footer>
            <a href="https://x.com/acmecorp">Follow on X</a>
            <a href="https://www.linkedin.com/company/acme-technologies/">LinkedIn</a>
            <a href="https://github.com/acme-org">GitHub</a>
            <a href="https://twitter.com/share?url=https://example.com">Share on Twitter (Ignore)</a>
            <a href="https://discord.gg/acmecommunity">Discord Community</a>
        </footer>
        """
        socials = extractor.extract_socials(html)
        assert "twitter" in socials
        assert "https://x.com/acmecorp" in socials["twitter"]
        assert "linkedin" in socials
        assert "https://www.linkedin.com/company/acme-technologies" in socials["linkedin"]
        assert "github" in socials
        assert "https://github.com/acme-org" in socials["github"]
        assert "discord" in socials
        assert "https://discord.gg/acmecommunity" in socials["discord"]
        # Share widget should be excluded
        assert not any("share" in url for url in socials.get("twitter", []))


class TestSchemaOrgJsonLdParser:
    """Test JSON-LD LocalBusiness and Organization entity parsing."""

    def test_parse_local_business_schema(self, extractor):
        """Extract structured business data, geo coordinates, and reviews."""
        json_ld = {
            "@context": "https://schema.org",
            "@type": "LocalBusiness",
            "name": "Apex Dental Clinic",
            "description": "Premier restorative and cosmetic dentistry",
            "telephone": "+1-212-555-0188",
            "email": "info@apexdental.com",
            "address": {
                "@type": "PostalAddress",
                "streetAddress": "123 Madison Ave",
                "addressLocality": "New York",
                "addressRegion": "NY",
                "postalCode": "10016",
                "addressCountry": "US",
            },
            "geo": {
                "@type": "GeoCoordinates",
                "latitude": 40.7484,
                "longitude": -73.9857,
            },
            "aggregateRating": {
                "@type": "AggregateRating",
                "ratingValue": 4.9,
                "reviewCount": 128,
            },
            "openingHours": ["Mo-Fr 08:00-17:00", "Sa 09:00-13:00"],
        }
        html = f'<script type="application/ld+json">{json.dumps(json_ld)}</script>'

        entities = extractor.parse_json_ld(html)
        assert len(entities) == 1
        entity = entities[0]

        assert entity.name == "Apex Dental Clinic"
        assert entity.telephone == "+1-212-555-0188"
        assert entity.email == "info@apexdental.com"
        assert entity.address is not None
        assert entity.address.locality == "New York"
        assert entity.address.postal_code == "10016"
        assert entity.geo is not None
        assert entity.geo.latitude == 40.7484
        assert entity.rating is not None
        assert entity.rating.rating_value == 4.9
        assert entity.rating.review_count == 128
        assert len(entity.opening_hours) == 2

    def test_parse_graph_array_schema(self, extractor):
        """Parse @graph container with multiple entities."""
        json_ld = {
            "@context": "https://schema.org",
            "@graph": [
                {"@type": "WebSite", "name": "Apex Site"},
                {
                    "@type": "Organization",
                    "name": "Apex Global Inc",
                    "url": "https://apexglobal.com",
                    "telephone": "+1-800-555-0199",
                },
            ],
        }
        html = f'<script type="application/ld+json">{json.dumps(json_ld)}</script>'
        entities = extractor.parse_json_ld(html)
        assert len(entities) == 1
        assert entities[0].name == "Apex Global Inc"


class TestLeadQualityScoreCalculation:
    """Test 0-100 Lead Quality Score weighting."""

    def test_perfect_score_100(self, extractor):
        """Full contact completeness earns 100 points."""
        addr = AddressData(street_address="100 Main St", locality="Austin", postal_code="78701")
        score = extractor.calculate_lead_score(
            emails=["ceo@startup.io"],
            phones=["(512) 555-0123"],
            address=addr,
            socials={"linkedin": ["https://linkedin.com/company/startup"]},
            has_ssl=True,
        )
        assert score == 100

    def test_partial_score(self, extractor):
        """Partial contact elements score proportionally."""
        # Email (+25) + SSL (+15) = 40
        score = extractor.calculate_lead_score(
            emails=["hello@startup.io"],
            phones=[],
            address=None,
            socials={},
            has_ssl=True,
        )
        assert score == 40

    def test_zero_score(self, extractor):
        """Empty profile receives 0 points."""
        score = extractor.calculate_lead_score(
            emails=[],
            phones=[],
            address=None,
            socials={},
            has_ssl=False,
        )
        assert score == 0


class TestEndToEndLeadExtraction:
    """Test extract_from_html end-to-end integration."""

    def test_extract_from_complete_html(self, extractor):
        """Extract all contact and intelligence vectors from comprehensive page."""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Stellar Cloud Solutions | Modern Infra</title>
            <script type="application/ld+json">
            {
                "@context": "https://schema.org",
                "@type": "Corporation",
                "name": "Stellar Cloud Solutions",
                "telephone": "+1-415-555-7788",
                "email": "contact@stellarcloud.io",
                "address": {
                    "@type": "PostalAddress",
                    "streetAddress": "500 Howard St",
                    "addressLocality": "San Francisco",
                    "addressRegion": "CA",
                    "postalCode": "94105",
                    "addressCountry": "US"
                }
            }
            </script>
        </head>
        <body>
            <a href="https://x.com/stellarcloud">X Profile</a>
            <a href="https://linkedin.com/company/stellar-cloud">LinkedIn Profile</a>
        </body>
        </html>
        """
        lead = extractor.extract_from_html(
            html=html,
            url="https://stellarcloud.io",
            has_ssl=True,
        )

        assert isinstance(lead, LeadData)
        assert lead.company_name == "Stellar Cloud Solutions"
        assert "contact@stellarcloud.io" in lead.emails
        assert any("7788" in p for p in lead.phones)
        assert "twitter" in lead.socials
        assert "linkedin" in lead.socials
        assert lead.has_ssl is True
        assert lead.lead_quality_score >= 85

        lead_dict = lead.to_dict()
        assert lead_dict["company_name"] == "Stellar Cloud Solutions"
        assert lead_dict["lead_quality_score"] >= 85
