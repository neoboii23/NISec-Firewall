"""Shared workspace navigation stays consistent without duplicate destinations."""
from html.parser import HTMLParser


class NavigationParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_navigation = False
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'nav' and attrs.get('id') == 'workspace-navigation':
            self.in_navigation = True
        if self.in_navigation and tag == 'a':
            self.links.append(attrs)

    def handle_endtag(self, tag):
        if tag == 'nav':
            self.in_navigation = False


def test_workspace_navigation_is_unique_and_marks_each_page(login):
    client, _ = login
    paths = ['/dashboard', '/logs', '/analytics', '/attack-map', '/alerts',
             '/rules', '/ip-management', '/rate-limits', '/evaluation', '/system', '/settings']
    for path in paths + ['/events', '/live-traffic']:
        response = client.get(path)
        assert response.status_code == 200
        parser = NavigationParser()
        parser.feed(response.get_data(as_text=True))
        assert len(parser.links) == 11
        assert len({link['href'] for link in parser.links}) == 11
        selected = [link for link in parser.links if link.get('aria-current') == 'page']
        assert len(selected) == 1
        assert selected[0]['href'] == ('/logs' if path in ['/events', '/live-traffic'] else path)
        assert all('nav-link' in link['class'] for link in parser.links)


def test_combined_traffic_page_keeps_live_data_filters_and_exports(login):
    client, _ = login
    response = client.get('/logs').get_data(as_text=True)
    for marker in ['Traffic &amp; logs', 'event-filters', 'recent-events',
                   'csv-export', 'json-export', 'prev-page', 'next-page']:
        assert marker in response
    assert 'aria-expanded="false"' in response
    assert 'aria-controls="workspace-navigation"' in response
