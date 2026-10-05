"""Rate limiting and /refresh authentication. Plain unittest, so it runs under pytest as well."""
import os
import unittest
from unittest import mock

import app as appmod
import protection

TOKEN = 'refresh-token-' + 'x' * 20          # 34 chars, above the 24-char minimum
PLAYER = ({'basicInfo': {'nickname': 'Tester', 'region': 'BD', 'bannerId': 1, 'headPic': 2}}, '14802881360', 'BD')
ENV_KEYS = ('REFRESH_TOKEN', 'REFRESH_COOLDOWN_SECONDS', 'RATE_LIMIT_INFO_PER_MIN', 'RATE_LIMIT_MEDIA_PER_MIN',
            'RATE_LIMIT_KEY_PER_MIN', 'RATE_LIMIT_REFRESH_FAIL_PER_MIN', 'API_KEYS', 'CLIENT_IP_HEADER',
            'RENDER', 'VERCEL')


class Base(unittest.TestCase):
    def setUp(self):
        saved = {k: os.environ.pop(k) for k in ENV_KEYS if k in os.environ}
        self.addCleanup(lambda: (self._clear(), os.environ.update(saved)))
        self.addCleanup(mock.patch.stopall)
        protection.limiter.reset()
        protection.reset_refresh_cooldown()
        self.c = appmod.app.test_client()

    @staticmethod
    def _clear():
        for k in ENV_KEYS:
            os.environ.pop(k, None)

    def env(self, **kw):
        os.environ.update({k: str(v) for k, v in kw.items()})


class RateLimitTests(Base):
    def setUp(self):
        super().setUp()
        mock.patch.object(appmod, 'get_player_data', return_value=PLAYER).start()

    def info(self, **headers):
        return self.c.get('/player-info?uid=14802881360', headers=headers)

    def test_blocks_after_limit_with_retry_after(self):
        self.env(RATE_LIMIT_INFO_PER_MIN=3)
        for _ in range(3):
            self.assertEqual(self.info().status_code, 200)
        r = self.info()
        self.assertEqual(r.status_code, 429)
        self.assertEqual(r.get_json()['code'], 'RATE_LIMITED')
        self.assertGreaterEqual(int(r.headers['Retry-After']), 1)

    def test_each_client_ip_has_its_own_limit(self):
        self.env(RATE_LIMIT_INFO_PER_MIN=1, CLIENT_IP_HEADER='CF-Connecting-IP')
        self.assertEqual(self.info(**{'CF-Connecting-IP': '203.0.113.5'}).status_code, 200)
        self.assertEqual(self.info(**{'CF-Connecting-IP': '203.0.113.5'}).status_code, 429)
        self.assertEqual(self.info(**{'CF-Connecting-IP': '203.0.113.6'}).status_code, 200)

    def test_zero_disables_limit(self):
        self.env(RATE_LIMIT_INFO_PER_MIN=0)
        for _ in range(40):
            self.assertEqual(self.info().status_code, 200)

    def test_api_key_gets_separate_limit_and_wrong_key_does_not(self):
        self.env(RATE_LIMIT_INFO_PER_MIN=1, API_KEYS='good-key-1234, other-key', RATE_LIMIT_KEY_PER_MIN=5)
        self.assertEqual(self.info().status_code, 200)
        self.assertEqual(self.info().status_code, 429)                      # public bucket is used up
        for _ in range(5):
            self.assertEqual(self.info(**{'X-API-Key': 'good-key-1234'}).status_code, 200)
        self.assertEqual(self.info(**{'X-API-Key': 'good-key-1234'}).status_code, 429)
        self.assertEqual(self.info(**{'X-API-Key': 'wrong'}).status_code, 429)  # falls back to the IP bucket

    def test_media_endpoints_are_limited(self):
        self.env(RATE_LIMIT_MEDIA_PER_MIN=2)
        mock.patch.object(appmod, 'get_player_data', side_effect=ValueError('bad uid')).start()
        codes = [self.c.get('/api/banner/banner_14802881360.webp').status_code for _ in range(3)]
        self.assertEqual(codes, [400, 400, 429])
        self.assertEqual(self.c.get('/api/avatar/avatar_14802881360.webp').status_code, 429)

    def test_pages_and_static_files_are_not_limited(self):
        self.env(RATE_LIMIT_INFO_PER_MIN=1, RATE_LIMIT_MEDIA_PER_MIN=1)
        for _ in range(10):
            self.assertEqual(self.c.get('/').status_code, 200)


class ClientIpTests(Base):
    def ip(self, headers=None, **environ):
        with appmod.app.test_request_context('/', headers=headers or {}, environ_base={'REMOTE_ADDR': '10.0.0.9'}):
            return protection.client_ip()

    def test_default_uses_socket_address_and_ignores_forwarded_headers(self):
        self.assertEqual(self.ip({'X-Forwarded-For': '1.2.3.4', 'CF-Connecting-IP': '1.2.3.4'}), '10.0.0.9')

    def test_render_uses_cloudflare_header_not_forwarded_for(self):
        self.env(RENDER='true')
        h = {'CF-Connecting-IP': '203.0.113.7', 'X-Forwarded-For': '198.51.100.1, 172.71.0.1, 10.1.1.1'}
        self.assertEqual(self.ip(h), '203.0.113.7')

    def test_malformed_or_missing_header_falls_back(self):
        self.env(RENDER='true')
        self.assertEqual(self.ip({'CF-Connecting-IP': 'not-an-ip'}), '10.0.0.9')
        self.assertEqual(self.ip(), '10.0.0.9')

    def test_vercel_uses_first_forwarded_for_entry(self):
        self.env(VERCEL='1')
        self.assertEqual(self.ip({'X-Forwarded-For': '203.0.113.9, 76.76.21.21'}), '203.0.113.9')


class RefreshTests(Base):
    def setUp(self):
        super().setUp()
        self.refresh_mock = mock.patch.object(appmod, 'initialize_tokens', new=mock.AsyncMock()).start()

    def post(self, **headers):
        return self.c.post('/refresh', headers=headers)

    def test_disabled_without_token(self):
        self.assertEqual(self.post(Authorization=f'Bearer {TOKEN}').status_code, 404)
        self.refresh_mock.assert_not_called()

    def test_short_token_counts_as_not_configured(self):
        self.env(REFRESH_TOKEN='short')
        self.assertEqual(self.post(Authorization='Bearer short').status_code, 404)

    def test_get_is_not_allowed(self):
        self.env(REFRESH_TOKEN=TOKEN)
        self.assertEqual(self.c.get('/refresh').status_code, 405)
        self.assertEqual(self.c.get(f'/refresh?token={TOKEN}').status_code, 405)
        self.refresh_mock.assert_not_called()

    def test_wrong_or_missing_token_is_401_and_does_nothing(self):
        self.env(REFRESH_TOKEN=TOKEN)
        self.assertEqual(self.post().status_code, 401)
        self.assertEqual(self.post(Authorization='Bearer nope').status_code, 401)
        self.assertEqual(self.post(Authorization=TOKEN).status_code, 401)     # no "Bearer" prefix
        self.refresh_mock.assert_not_called()

    def test_correct_token_refreshes(self):
        self.env(REFRESH_TOKEN=TOKEN)
        r = self.post(Authorization=f'Bearer {TOKEN}')
        self.assertEqual(r.status_code, 200)
        self.refresh_mock.assert_called_once()

    def test_x_refresh_token_header_also_works(self):
        self.env(REFRESH_TOKEN=TOKEN)
        self.assertEqual(self.post(**{'X-Refresh-Token': TOKEN}).status_code, 200)

    def test_cooldown_blocks_repeat_refreshes(self):
        self.env(REFRESH_TOKEN=TOKEN, REFRESH_COOLDOWN_SECONDS=60)
        self.assertEqual(self.post(Authorization=f'Bearer {TOKEN}').status_code, 200)
        r = self.post(Authorization=f'Bearer {TOKEN}')
        self.assertEqual(r.status_code, 429)
        self.assertIn('Retry-After', r.headers)
        self.assertEqual(self.refresh_mock.call_count, 1)

    def test_repeated_wrong_tokens_get_rate_limited(self):
        self.env(REFRESH_TOKEN=TOKEN, RATE_LIMIT_REFRESH_FAIL_PER_MIN=3)
        codes = [self.post(Authorization='Bearer wrong').status_code for _ in range(5)]
        self.assertEqual(codes, [401, 401, 401, 429, 429])


if __name__ == '__main__':
    unittest.main()
