"""Unit tests for subsweep_lead_scanner.tech_profiler module."""

from unittest.mock import MagicMock, patch
import urllib.error

import pytest
from subsweep_lead_scanner.tech_profiler import (
    CATEGORY_ANALYTICS,
    CATEGORY_BACKEND,
    CATEGORY_CMS,
    CATEGORY_FRONTEND,
    CATEGORY_HOSTING,
    CATEGORY_SECURITY,
    TechnologyProfiler,
    TechProfileResult,
)


@pytest.fixture
def profiler() -> TechnologyProfiler:
    """Instantiate TechnologyProfiler instance."""
    return TechnologyProfiler()


class TestDomParsingAndUtilities:
    """Test HTML and header parser helper methods."""

    def test_extract_meta_tags(self, profiler):
        """Extract various meta tags case-insensitively."""
        html = """
        <html>
            <head>
                <meta name="generator" content="WordPress 6.4.2" />
                <meta property="OG:Title" content="My Store" />
                <meta http-equiv="Content-Security-Policy" content="default-src 'self'" />
            </head>
        </html>
        """
        metas = profiler.extract_meta_tags(html)
        assert metas.get("generator") == "WordPress 6.4.2"
        assert metas.get("og:title") == "My Store"
        assert metas.get("content-security-policy") == "default-src 'self'"

    def test_extract_scripts(self, profiler):
        """Extract script src URLs and inline blocks."""
        html = """
        <html>
            <head>
                <script src="https://cdn.example.com/assets/app.js"></script>
                <script>
                    window.__NEXT_DATA__ = { props: {} };
                </script>
            </head>
        </html>
        """
        scripts = profiler.extract_scripts(html)
        assert len(scripts) == 2
        assert "https://cdn.example.com/assets/app.js" in scripts[0]
        assert "__NEXT_DATA__" in scripts[1]

    def test_check_security_headers(self, profiler):
        """Evaluate security posture based on HTTP headers."""
        headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "camera=(), microphone=()",
        }
        checks, score = profiler.check_security_headers(headers)
        assert checks["hsts"] is True
        assert checks["csp"] is True
        assert checks["x_frame_options"] is True
        assert score == 100


class TestFrameworkFingerprints:
    """Test frontend and JavaScript framework recognition."""

    def test_detect_nextjs(self, profiler):
        """Detect Next.js via DOM and headers."""
        html = '<div id="__next"><script src="/_next/static/chunks/main.js"></script></div>'
        headers = {"x-powered-by": "Next.js", "x-vercel-id": "iad1::123"}
        res = profiler.profile_html(html, headers)

        tech_names = [t.name for t in res.technologies]
        assert "Next.js" in tech_names
        assert "Vercel" in tech_names
        assert CATEGORY_FRONTEND in res.categories
        assert "Next.js" in res.categories[CATEGORY_FRONTEND]

    def test_detect_react(self, profiler):
        """Detect React via root DOM attributes."""
        html = '<div id="root" data-reactroot=""><script src="react-dom.production.min.js"></script></div>'
        res = profiler.profile_html(html)
        assert any(t.name == "React" for t in res.technologies)

    def test_detect_vue_and_nuxt(self, profiler):
        """Detect Vue and Nuxt."""
        html = '<div id="__nuxt" data-v-4a2c1e8><script>window.__NUXT__={};</script></div>'
        headers = {"x-powered-by": "Nuxt"}
        res = profiler.profile_html(html, headers)
        tech_names = [t.name for t in res.technologies]
        assert "Nuxt.js" in tech_names
        assert "Vue.js" in tech_names

    def test_detect_svelte(self, profiler):
        """Detect Svelte components."""
        html = '<div class="svelte-19m8a1b svelte-xyz">Hello Svelte</div>'
        res = profiler.profile_html(html)
        assert any(t.name == "Svelte" for t in res.technologies)

    def test_detect_angular(self, profiler):
        """Detect Angular version and directives."""
        html = '<app-root ng-version="17.2.1" _ngcontent-c0></app-root>'
        res = profiler.profile_html(html)
        match = next(t for t in res.technologies if t.name == "Angular")
        assert match.version == "17.2.1"

    def test_detect_astro(self, profiler):
        """Detect Astro static generator."""
        html = '<meta name="generator" content="Astro v4.5.0"><astro-island></astro-island>'
        res = profiler.profile_html(html)
        match = next(t for t in res.technologies if t.name == "Astro")
        assert match.version == "4.5.0"

    def test_detect_tailwind_and_bootstrap(self, profiler):
        """Detect CSS frameworks."""
        html_tailwind = '<div class="flex items-center justify-between bg-slate-900 rounded-lg p-4"></div>'
        res_tw = profiler.profile_html(html_tailwind)
        assert any(t.name == "Tailwind CSS" for t in res_tw.technologies)

        html_bootstrap = '<div class="container-fluid"><div class="col-md-6"></div></div>'
        res_bs = profiler.profile_html(html_bootstrap)
        assert any(t.name == "Bootstrap" for t in res_bs.technologies)


class TestCmsFingerprints:
    """Test Content Management Systems detection."""

    def test_detect_wordpress(self, profiler):
        """Detect WordPress and version."""
        html = """
        <meta name="generator" content="WordPress 6.4.3" />
        <link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css" />
        <script src="/wp-includes/js/wp-emoji-release.min.js"></script>
        """
        headers = {"link": '<https://example.com/wp-json/>; rel="https://api.w.org/"'}
        res = profiler.profile_html(html, headers)
        match = next(t for t in res.technologies if t.name == "WordPress")
        assert match.version == "6.4.3"
        assert match.confidence >= 80

    def test_detect_shopify(self, profiler):
        """Detect Shopify e-commerce platform."""
        html = '<script src="https://cdn.shopify.com/s/files/1/0001/theme.js"></script><script>Shopify.theme={};</script>'
        headers = {"x-shopify-stage": "production"}
        res = profiler.profile_html(html, headers)
        assert any(t.name == "Shopify" for t in res.technologies)

    def test_detect_webflow(self, profiler):
        """Detect Webflow site builder."""
        html = '<html data-wf-page="64abc123" data-wf-site="64abc456"><script src="https://assets.website-files.com/webflow.js"></script>'
        res = profiler.profile_html(html)
        assert any(t.name == "Webflow" for t in res.technologies)

    def test_detect_squarespace_and_wix(self, profiler):
        """Detect Squarespace and Wix platforms."""
        html_sq = '<meta name="generator" content="Squarespace" /><script src="https://static1.squarespace.com/static/site.js"></script>'
        res_sq = profiler.profile_html(html_sq)
        assert any(t.name == "Squarespace" for t in res_sq.technologies)

        html_wix = '<meta name="generator" content="Wix.com" /><script src="https://static.wixstatic.com/wix.js"></script>'
        res_wix = profiler.profile_html(html_wix)
        assert any(t.name == "Wix" for t in res_wix.technologies)


class TestHostingAndCdnFingerprints:
    """Test Hosting and CDN infrastructure recognition."""

    def test_detect_cloudflare(self, profiler):
        """Detect Cloudflare edge and proxy."""
        headers = {
            "server": "cloudflare",
            "cf-ray": "85728a1c9df84a2b-EWR",
            "cf-cache-status": "HIT",
        }
        res = profiler.profile_html("<html></html>", headers)
        assert any(t.name == "Cloudflare" for t in res.technologies)

    def test_detect_netlify_and_cloudfront(self, profiler):
        """Detect Netlify and AWS CloudFront."""
        headers_net = {"server": "Netlify", "x-nf-request-id": "01HPX7K9"}
        res_net = profiler.profile_html("", headers_net)
        assert any(t.name == "Netlify" for t in res_net.technologies)

        headers_cf = {"via": "1.1 abc.cloudfront.net (CloudFront)", "x-amz-cf-id": "xyz987=="}
        res_cf = profiler.profile_html("", headers_cf)
        assert any(t.name == "AWS CloudFront" for t in res_cf.technologies)


class TestAnalyticsAndMarketingFingerprints:
    """Test analytics and tracking pixels detection."""

    def test_detect_google_analytics_and_meta_pixel(self, profiler):
        """Detect Google Analytics GA4 / GTM and Meta Pixel."""
        html = """
        <script async src="https://www.googletagmanager.com/gtm.js?id=GTM-ABCDEF"></script>
        <script>
            gtag('config', 'G-1234567890');
            fbq('init', '987654321');
        </script>
        <script src="https://connect.facebook.net/en_US/fbevents.js"></script>
        """
        res = profiler.profile_html(html)
        tech_names = [t.name for t in res.technologies]
        assert "Google Analytics / GTM" in tech_names
        assert "Meta Pixel" in tech_names

    def test_detect_posthog_and_hotjar(self, profiler):
        """Detect PostHog and Hotjar."""
        html = """
        <script>
            posthog.init('phc_test_123', { api_host: 'https://us.i.posthog.com' });
        </script>
        <script src="https://static.hotjar.com/c/hotjar-12345.js"></script>
        """
        res = profiler.profile_html(html)
        tech_names = [t.name for t in res.technologies]
        assert "PostHog" in tech_names
        assert "Hotjar" in tech_names


class TestBackendFingerprints:
    """Test backend framework signatures."""

    def test_detect_django_and_laravel(self, profiler):
        """Detect Django and Laravel through cookies and tokens."""
        res_django = profiler.profile_html(
            '<input type="hidden" name="csrfmiddlewaretoken" value="abc123xyz">',
            {"set-cookie": "csrftoken=abc123xyz; Path=/"},
        )
        assert any(t.name == "Django" for t in res_django.technologies)

        res_laravel = profiler.profile_html(
            '<meta name="csrf-token" content="token123">',
            {"set-cookie": "laravel_session=session456; Path=/", "x-powered-by": "PHP/Laravel"},
        )
        assert any(t.name == "Laravel" for t in res_laravel.technologies)


class TestRemoteProfileUrl:
    """Test remote profile URL fetcher with mocks."""

    @patch("urllib.request.urlopen")
    def test_profile_url_success(self, mock_urlopen, profiler):
        """Profile remote URL successfully."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"server": "cloudflare", "x-powered-by": "Next.js"}
        mock_resp.read.return_value = b'<html><div id="__next"></div></html>'
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        res = profiler.profile_url("https://example.com")
        assert res.status_code == 200
        assert any(t.name == "Next.js" for t in res.technologies)
        assert any(t.name == "Cloudflare" for t in res.technologies)
        assert res.overall_confidence > 0
