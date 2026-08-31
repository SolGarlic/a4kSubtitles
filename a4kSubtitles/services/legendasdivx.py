# -*- coding: utf-8 -*-
#
# LegendasDivx.pt service for a4kSubtitles.
#
# LegendasDivx.pt requires a registered account (new registrations require
# an invite from an existing member). There is no JSON API: authentication
# is a phpBB forum login, search results are HTML, and downloads return a
# raw .rar/.zip archive.
#
# The search endpoint (GET .../modules.php?name=Downloads&file=jz
# &d_op=search&op=_jz00&query=<query>) returns BOTH Portuguese and
# Brazilian Portuguese results mixed in the same page when no form_cat
# filter is passed - the language of each result is only recoverable
# from the flag image filename in that result's block
# (modules/Downloads/img/portugal.gif vs .../brazil.gif). So this service
# fires a single request per search and splits languages while parsing,
# rather than one request per language like most other a4kSubtitles
# services do.
#
# Regexes below were built and verified against a real captured search
# results page from the site (August 2026).

import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

__main_url = 'https://www.legendasdivx.pt/'
__login_url = __main_url + 'forum/ucp.php?mode=login'
__search_url = __main_url + 'modules.php?name=Downloads&file=jz&d_op=search&op=_jz00'
__download_url = __main_url + 'modules.php?name=Downloads&d_op=getit&lid=%s'
__user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
__date_format = '%Y-%m-%d %H:%M:%S'
__sub_exts = ('.srt', '.sub', '.ssa', '.ass', '.smi', '.txt')
# Bump this whenever the login flow changes. A cached cookie written by an
# older version (e.g. before the CSRF-token fix) is silently reused by
# build_auth_request based on its ttl alone - it has no way to know the
# cookie was never actually valid. Comparing this version forces a fresh
# login the first time this code runs, regardless of leftover ttl.
__auth_version = 2

__lang_image_map = {
    'portugal': 'Portuguese',
    'brazil': 'Portuguese (Brazil)',
}

def __get_cookie_header(core, service_name):
    if core.os.getenv('A4KSUBTITLES_TESTRUN') == 'true':
        return None

    cache = core.cache.get_tokens_cache()
    token_cache = cache.get(service_name, None)
    return token_cache['cookie'] if token_cache else None

def __parse_login_tokens(page_html):
    token_match = re.search(r'name="form_token"\s+value="([^"]*)"', page_html)
    creation_match = re.search(r'name="creation_time"\s+value="([^"]*)"', page_html)
    sid_match = re.search(r'name="sid"\s+value="([^"]*)"', page_html)
    return {
        'form_token': token_match.group(1) if token_match else '',
        'creation_time': creation_match.group(1) if creation_match else '',
        'sid': sid_match.group(1) if sid_match else '',
    }

def __parse_login_error(page_html):
    # On failed login (wrong username/password), phpBB re-renders the
    # login form with a "<div class="error">...</div>" block containing a
    # human-readable reason (e.g. "A Senha introduzida não está correta").
    # Surfacing this distinguishes real bad-credentials failures from the
    # CSRF/session bug that also results in logged_in=False further down.
    error_match = re.search(r'<div class="error">(.*?)</div>', page_html, re.DOTALL)
    return __clean_html(error_match.group(1)) if error_match else None

def build_auth_request(core, service_name):
    if core.os.getenv('A4KSUBTITLES_TESTRUN') == 'true':
        return

    cache = core.cache.get_tokens_cache()
    token_cache = cache.get(service_name, None)
    if token_cache is not None and token_cache.get('auth_version') == __auth_version and 'ttl' in token_cache:
        token_ttl = core.datetime.fromtimestamp(core.time.mktime(core.time.strptime(token_cache['ttl'], __date_format)))
        if token_ttl > core.datetime.now():
            return

    cache.pop(service_name, None)
    core.cache.save_tokens_cache(cache)

    username = core.kodi.get_setting(service_name, 'username')
    password = core.kodi.get_setting(service_name, 'password')

    if username == '' or password == '':
        core.kodi.notification('LegendasDivx requires authentication! Enter username/password in the addon Settings->Accounts or disable the service.')
        return

    def submit_login(login_page_response):
        # phpBB requires the form_token/creation_time/sid from a freshly
        # loaded login page to accept the login (CSRF protection). Posting
        # credentials without them is silently accepted by the server but
        # never actually authenticates - it just returns a guest session
        # (cookie's "_u" value stays "1", phpBB's reserved anonymous id).
        tokens = __parse_login_tokens(login_page_response.text)

        # Framework workaround: lib/request.py's execute() always opens a
        # brand new requests.session() for non-cfscrape requests (the
        # 'else' branch ignores the 'session' argument chained through
        # 'next'), so the session/sid cookie phpBB set on this GET never
        # reaches the POST below. Without it, the sid we just extracted
        # from the HTML doesn't match any session the server tracks for
        # the POST, CSRF validation fails silently, and phpBB falls back
        # to a guest login. Forward the GET's cookies explicitly to
        # compensate.
        login_cookies = login_page_response.cookies.get_dict()
        cookie_header = '; '.join('%s=%s' % (key, value) for key, value in login_cookies.items())

        headers = {
            'User-Agent': __user_agent,
            'Referer': __login_url,
        }
        if cookie_header:
            headers['Cookie'] = cookie_header

        return {
            'method': 'POST',
            'url': __login_url,
            'data': {
                'username': username,
                'password': password,
                'login': 'Login',
                'sid': tokens['sid'],
                'creation_time': tokens['creation_time'],
                'form_token': tokens['form_token'],
                'redirect': 'index.php',
            },
            'headers': headers,
        }

    request = {
        'method': 'GET',
        'url': __login_url,
        'headers': {
            'User-Agent': __user_agent,
        },
        'next': submit_login,
    }

    return request

def __extract_phpbb_error(page_html):
    error_match = re.search(r'<div class="error">(.*?)</div>', page_html, re.DOTALL)
    return __clean_html(error_match.group(1)) if error_match else None

def parse_auth_response(core, service_name, response):
    if response.status_code != 200:
        core.kodi.notification('LegendasDivx authentication failed! Check your username and password.')
        return

    # On a successful login phpBB issues a 302 redirect (to the 'redirect'
    # target we posted) carrying the Set-Cookie for the real, authenticated
    # "_u" value. requests follows that redirect automatically, but the
    # final Response object's own .cookies only holds cookies set by the
    # *last* hop in the chain - the redirect target page usually doesn't
    # re-send Set-Cookie, so the "_u" cookie that mattered is only visible
    # on the intermediate 302 response, kept in response.history. Merge
    # cookies across the whole chain instead of just the final response.
    cookies = {}
    for hist_response in response.history:
        cookies.update(hist_response.cookies.get_dict())
    cookies.update(response.cookies.get_dict())

    user_id_cookie = next((v for k, v in cookies.items() if k.endswith('_u')), None)
    # phpBB user id "1" is the reserved anonymous/guest account - if that's
    # still the value after "logging in", authentication did not actually
    # succeed even though the server returned 200 and set cookies.
    logged_in = (user_id_cookie is not None and user_id_cookie != '1') or 'mode=logout' in response.text

    core.logger.debug(
        '%s - login cookie _u=%s, logged_in=%s, history=%d' %
        (service_name, user_id_cookie, logged_in, len(response.history))
    )

    if not logged_in:
        phpbb_error = __extract_phpbb_error(response.text)
        message = 'LegendasDivx authentication failed! %s' % phpbb_error if phpbb_error else \
            'LegendasDivx authentication failed! Check your username and password.'
        core.logger.debug('%s - %s' % (service_name, message))
        core.kodi.notification(message)
        return

    # Login succeeded.

    cookie_header = '; '.join('%s=%s' % (key, value) for key, value in cookies.items())

    token_cache = {
        'cookie': cookie_header,
        'ttl': (core.datetime.now() + core.timedelta(hours=6)).strftime(__date_format),
        'auth_version': __auth_version,
    }

    cache = core.cache.get_tokens_cache()
    cache[service_name] = token_cache
    core.cache.save_tokens_cache(cache)

def __build_query(meta):
    # The site's search accepts a plain IMDb id ("tt1234567") directly and
    # matches it precisely - verified working for movies. For TV episodes
    # meta.imdb_id is the *episode-specific* id (not the show's), which
    # won't match anything, so fall back to text search there.
    if not meta.is_tvshow and meta.imdb_id:
        return meta.imdb_id

    if meta.is_tvshow:
        return '%s S%.2dE%.2d' % (meta.tvshow, int(meta.season), int(meta.episode))

    return '%s %s' % (meta.title, meta.year)

def build_search_requests(core, service_name, meta):
    cookie_header = __get_cookie_header(core, service_name)
    if cookie_header is None and core.os.getenv('A4KSUBTITLES_TESTRUN') != 'true':
        return []

    lang_ids = core.utils.get_lang_ids(meta.languages, core.kodi.xbmc.ISO_639_1)
    if not any(lang in ('pt', 'pt-br') for lang in lang_ids):
        return []

    query = __build_query(meta)

    headers = {
        'User-Agent': __user_agent,
        'Referer': __main_url + 'modules.php?name=Downloads&file=jz',
    }
    if cookie_header:
        headers['Cookie'] = cookie_header

    request = {
        'method': 'GET',
        'url': __search_url,
        'params': {
            'query': query,
        },
        'headers': headers,
        # legendasdivx.pt sits behind Cloudflare; the login endpoint tolerates
        # a plain requests session, but the search endpoint doesn't - it
        # returns 200 with an empty page (no <div class="sub_box"> blocks)
        # unless routed through cloudscraper. Verified: the exact same URL,
        # query and cookies return real results from a browser but nothing
        # from a plain HTTP client.
        'cfscrape': True,
    }

    return [request]

def __clean_html(text):
    # Non-greedy + DOTALL instead of the nested-quantifier version below -
    # the nested form is a classic ReDoS pattern: it backtracks
    # catastrophically (effectively hangs) whenever a "<script" appears
    # without a matching "</script>" in the same string, which happens
    # routinely here since these blocks are slices of the page cut by
    # re.split() and a script tag can straddle a slice boundary.
    #   text = re.sub(r'<script\b[^<]*(?:(?!</script>)<[^<]*)*</script>', '', text, flags=re.IGNORECASE)
    text = re.sub(r'<script\b.*?</script>', '', text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r'<br\s*/?>', ' ', text)
    text = re.sub(r'\n', ' ', text)
    text = re.sub(r'<[^<]+?>|[~]', '', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()

def __episode_covered(kodi_e, episode_values):
    for val in episode_values:
        if val == 'pack':
            return True
        if '-' in val:
            try:
                lo, hi = val.split('-')
                if int(lo) <= kodi_e <= int(hi):
                    return True
            except ValueError:
                continue
        else:
            try:
                if int(val) == kodi_e:
                    return True
            except ValueError:
                continue
    return False

def parse_search_response(core, service_name, meta, response):
    content = response.text
    service = core.services[service_name]
    results = []

    sub_box_count = content.count('<div class="sub_box">')
    if sub_box_count == 0:
        # No results blocks at all - distinguish "search genuinely empty"
        # from "got blocked/redirected before reaching real results" so
        # this doesn't need re-diagnosing from scratch next time.
        looks_blocked = 'cf-browser-verification' in content or 'Just a moment' in content or 'Attention Required' in content
        looks_logged_out = 'mode=login' in content and 'mode=logout' not in content
        core.logger.debug(
            '%s - 0 sub_box blocks, len=%d, looks_blocked=%s, looks_logged_out=%s' %
            (service_name, len(content), looks_blocked, looks_logged_out)
        )

    for block in re.split(r'<div class="sub_box">', content)[1:]:
        lid_match = re.search(r'name=Downloads&d_op=getit&lid=(\d+)', block)
        if not lid_match:
            continue
        sub_id = lid_match.group(1)

        lang_img_match = re.search(r'src="modules/Downloads/img/(\w+)\.gif"', block)
        lang_img = lang_img_match.group(1).lower() if lang_img_match else ''
        lang = __lang_image_map.get(lang_img)
        if lang is None or lang not in meta.languages:
            continue

        header_match = re.search(r'<b>(.*?)</b>\s*\((\d{4})\)', block, re.DOTALL)
        name = __clean_html(header_match.group(1)) if header_match else 'Legenda'
        year = header_match.group(2) if header_match else ''

        uploader_match = re.search(r"username=([^']+)'>", block)
        uploader = uploader_match.group(1) if uploader_match else 'Unknown'

        hits_match = re.search(r'Hits:</th>\s*<td>(\d+)', block)
        hits = hits_match.group(1) if hits_match else '0'

        desc_match = re.search(r'class="td_desc brd_up">(.*?)</td>', block, re.DOTALL)
        desc = __clean_html(desc_match.group(1)) if desc_match else ''

        if meta.is_tvshow:
            kodi_s = int(meta.season)
            kodi_e = int(meta.episode)

            season_select = re.search(r'<select id="temporada-\d+"[^>]*>(.*?)</select>', block, re.DOTALL)
            episode_select = re.search(r'<select id="episodio-\d+"[^>]*>(.*?)</select>', block, re.DOTALL)

            if season_select and episode_select:
                season_opt = re.search(r'<option value="(\d+)"[^>]*selected="selected"', season_select.group(1))
                web_season = season_opt.group(1) if season_opt else None
                episode_values = [v for v in re.findall(r'<option value="([^"]+)"', episode_select.group(1)) if v != '-1']

                if web_season:
                    try:
                        if len(web_season) == 4:
                            lo, hi = int(web_season[:2]), int(web_season[2:])
                            if not (lo <= kodi_s <= hi):
                                continue
                        elif int(web_season) != kodi_s:
                            continue
                    except ValueError:
                        pass

                if episode_values and not __episode_covered(kodi_e, episode_values):
                    continue
            else:
                # no season/episode selects on this block (older/movie-style
                # entry) - fall back to matching SxxEyy in the name/description
                pattern = re.compile(
                    r'(s%02de%02d|\b%dx%02d\b|\be%02d\b)' % (kodi_s, kodi_e, kodi_s, kodi_e, kodi_e),
                    re.IGNORECASE
                )
                if not (pattern.search(name) or pattern.search(desc)):
                    continue

        try:
            rating = min(5, int(round(int(hits) / 200)))
        except (ValueError, ZeroDivisionError):
            rating = 0

        sync = meta.filename_without_ext.lower() in desc.lower() if meta.filename_without_ext else False
        display_name = 'From: %s - %s' % (uploader, name)
        if year:
            display_name += ' (%s)' % year
        if desc:
            display_name += ' - %s' % desc

        results.append({
            'service_name': service_name,
            'service': service.display_name,
            'lang': lang,
            'name': display_name,
            'rating': rating,
            'lang_code': core.utils.get_lang_id(lang, core.kodi.xbmc.ISO_639_1),
            'sync': 'true' if sync else 'false',
            'impaired': 'false',
            'color': 'orange',
            'action_args': {
                'url': __download_url % sub_id,
                'id': sub_id,
                'lang': lang,
                'filename': display_name,
            },
        })

    return results

class __OneShotZipHandler(BaseHTTPRequestHandler):
    # Set per-instance by __serve_zip_once() via a closure-friendly subclass.
    zip_bytes = b''

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/zip')
        self.send_header('Content-Length', str(len(self.zip_bytes)))
        self.end_headers()
        self.wfile.write(self.zip_bytes)

    def log_message(self, format, *log_args):
        pass  # silence BaseHTTPRequestHandler's default stderr access log

def __serve_zip_once(zip_bytes):
    # a4kSubtitles' download.py always saves the downloaded file as
    # "sub.zip" and only ever tries to open it with archive:// (never
    # rar://), so a real RAR archive can never be extracted there no
    # matter what Kodi VFS add-ons are installed. Rather than touching
    # that shared framework file, we do the RAR->ZIP conversion here and
    # hand back a URL to a one-shot local HTTP server serving the
    # corrected, standards-compliant ZIP - download.py then downloads it
    # exactly like any other URL and its own Python zipfile.ZipFile call
    # (its first, normal attempt) opens it with no changes needed there.
    handler_cls = type('_Handler', (__OneShotZipHandler,), {'zip_bytes': zip_bytes})
    httpd = HTTPServer(('127.0.0.1', 0), handler_cls)
    port = httpd.server_port
    thread = threading.Thread(target=httpd.handle_request)
    thread.daemon = True
    thread.start()
    return 'http://127.0.0.1:%d/sub.zip' % port

def __extract_rar_member_via_vfs(core, rar_path):
    rar_vfs = 'rar://%s/' % core.utils.quote_plus(rar_path)

    try:
        dirs, files = core.kodi.xbmcvfs.listdir(rar_vfs)
    except Exception as exc:
        core.logger.debug('legendasdivx - rar:// listdir failed (is vfs.rar installed?): %s' % exc)
        return None

    candidates = [(rar_vfs + f, f) for f in files if f.lower().endswith(__sub_exts)]
    for d in dirs:
        sub_vfs = rar_vfs + d + '/'
        try:
            _, sub_files = core.kodi.xbmcvfs.listdir(sub_vfs)
        except Exception:
            continue
        candidates.extend((sub_vfs + f, f) for f in sub_files if f.lower().endswith(__sub_exts))

    if not candidates:
        return None

    src, member_name = candidates[0]
    dest = core.os.path.join(core.utils.temp_dir, member_name)
    if not core.kodi.xbmcvfs.copy(src, dest):
        return None

    with open(dest, 'rb') as f:
        sub_bytes = f.read()

    try: core.os.remove(dest)
    except: pass

    return (member_name, sub_bytes)

def __repackage_as_zip(core, content, sub_id):
    if len(content) < 4:
        return None

    header = content[:4]

    if header[:2] == b'PK':
        return None  # already a proper ZIP - let download.py handle it as-is

    if header != b'Rar!':
        return None  # not RAR either (raw subtitle, HTML error page, etc.) - don't touch it

    rar_path = core.os.path.join(core.utils.temp_dir, 'ldivx_%s.rar' % sub_id)
    try:
        core.kodi.xbmcvfs.mkdirs(core.utils.temp_dir)
        with open(rar_path, 'wb') as f:
            f.write(content)

        extracted = __extract_rar_member_via_vfs(core, rar_path)
        if extracted is None:
            # This is ground truth (unlike checking the addon-enabled flag
            # via JSON-RPC, which can report "enabled" even when the
            # native rar:// handler isn't actually functional): we just
            # tried to use rar:// on a real download and it failed, so we
            # know for a fact vfs.rar isn't working right now.
            core.logger.debug('legendasdivx - could not extract subtitle from RAR via rar:// VFS')
            core.kodi.notification(
                'LegendasDivx: esta legenda vem num RAR e não foi possível '
                'extraí-la. Confirma que o addon "RAR support" (vfs.rar) '
                'está instalado e ativado.'
            )
            return None

        member_name, sub_bytes = extracted

        buffer = core.BytesIO()
        with core.zipfile.ZipFile(buffer, 'w') as zf:
            zf.writestr(member_name, sub_bytes)
        return buffer.getvalue()
    except Exception as exc:
        core.logger.debug('legendasdivx - RAR to ZIP repackage failed: %s' % exc)
        return None
    finally:
        try: core.os.remove(rar_path)
        except: pass

def build_download_request(core, service_name, args):
    cookie_header = __get_cookie_header(core, service_name)

    headers = {'User-Agent': __user_agent}
    if cookie_header:
        headers['Cookie'] = cookie_header

    request = {
        'method': 'GET',
        'url': __download_url % args['id'],
        'headers': headers,
        'cfscrape': True,
    }

    try:
        response = core.request.execute(core, dict(request), progress=False)
        content = response.content
    except Exception as exc:
        core.logger.debug('legendasdivx - download prefetch failed, falling back to direct URL: %s' % exc)
        return request

    zip_bytes = __repackage_as_zip(core, content, args.get('id', 'sub'))
    if zip_bytes is None:
        return request  # not RAR, or repackage failed - let download.py handle the original response

    local_url = __serve_zip_once(zip_bytes)
    return {
        'method': 'GET',
        'url': local_url,
    }
