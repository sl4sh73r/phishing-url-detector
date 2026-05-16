package ru.mirea.phishing;

import java.net.URI;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Извлекает признаки UCI Phishing Websites из URL.
 * <p>
 * Только <b>лексические</b> признаки — без сетевых запросов (HTTPS, WHOIS, DNS),
 * чтобы demo не падал на защите при проблемах с интернетом.
 * Недоступные «сетевые» признаки получают значение 0 (нейтрально — между «1» и «-1»).
 * <p>
 * Имена и значения признаков соответствуют датасету
 * Mohammad, Thabtah, McCluskey (2015): {-1, 0, 1}.
 */
public final class UrlFeatureExtractor {

    /** Порядок признаков должен совпадать с ARFF. */
    public static final List<String> FEATURE_NAMES = List.of(
            "having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
            "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
            "Domain_registeration_length", "Favicon", "port", "HTTPS_token",
            "Request_URL", "URL_of_Anchor", "Links_in_tags", "SFH",
            "Submitting_to_email", "Abnormal_URL", "Redirect", "on_mouseover",
            "RightClick", "popUpWidnow", "Iframe", "age_of_domain",
            "DNSRecord", "web_traffic", "Page_Rank", "Google_Index",
            "Links_pointing_to_page", "Statistical_report"
    );

    private static final Pattern IPV4 = Pattern.compile(
            "^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");

    private static final Set<String> SHORTENERS = Set.of(
            "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
            "buff.ly", "adf.ly", "tiny.cc", "lnkd.in", "vk.cc", "clck.ru",
            "shrtco.de", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy"
    );

    /**
     * Free / cheap TLDs которые массово используются для фишинговых кампаний
     * (статистика Spamhaus, APWG: эти зоны дают ~50% всего фишинга).
     */
    private static final Set<String> SUSPICIOUS_TLDS = Set.of(
            ".tk", ".cf", ".ml", ".gq", ".ga",       // Freenom (бесплатные)
            ".pw", ".top", ".xyz", ".click", ".link", // дешёвые
            ".loan", ".work", ".date", ".racing",
            ".accountant", ".cricket", ".country", ".stream"
    );

    /** Английские лексические триггеры (бренды + фишинговые глаголы). */
    private static final String[] EN_TRIGGERS = {
            "paypal", "login", "verify", "secure", "account", "update", "confirm",
            "signin", "sign-in", "ebay", "apple", "icloud", "amazon", "wallet",
            "bank", "banking", "card", "password", "support", "recovery",
            "microsoft", "office365", "outlook", "google", "drive", "dropbox",
            "facebook", "instagram", "netflix", "spotify", "crypto", "binance",
            "metamask", "telegram", "whatsapp"
    };

    /** Русские лексические триггеры. */
    private static final String[] RU_TRIGGERS = {
            "вход", "логин", "пароль", "оплат", "акк", "карт", "счет", "счёт",
            "банк", "сбер", "тинькоф", "альфа", "втб", "почта", "налог", "госуслуг",
            "выигр", "приз", "лотер", "акци", "скидк", "подар",
            "крипт", "обмен", "кошел", "ставк", "казино", "букмекер",
            "вор", "украд", "взлом", "хак", "взять", "получ",
            "куплю", "продам", "обмен", "ставки",
            "support", "поддерж"
    };

    private UrlFeatureExtractor() {}

    /**
     * Извлекает все 30 признаков. Возвращает double[30] в порядке {@link #FEATURE_NAMES}.
     */
    public static double[] extract(String url) {
        String normalized = url.trim();
        if (!normalized.matches("^https?://.*")) {
            normalized = "http://" + normalized;
        }

        URI uri;
        try {
            uri = URI.create(normalized);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid URL: " + url, e);
        }

        String host = uri.getHost() == null ? "" : uri.getHost();
        String path = uri.getRawPath() == null ? "" : uri.getRawPath();
        String full = normalized;
        String hostLower = host.toLowerCase();
        boolean hasNonAsciiHost = host.chars().anyMatch(c -> c > 127);
        boolean hasPunycode = hostLower.contains("xn--"); // Punycode-кодированный IDN
        boolean idnAttack = hasNonAsciiHost || hasPunycode;

        double[] f = new double[FEATURE_NAMES.size()];

        // 1. having_IP_Address: -1 если домен — IP, иначе 1
        f[0] = IPV4.matcher(host).matches() ? -1 : 1;

        // 2. URL_Length: 1 (< 54), 0 (54-74), -1 (≥ 75)
        int len = full.length();
        f[1] = len < 54 ? 1 : (len <= 74 ? 0 : -1);

        // 3. Shortining_Service: -1 если домен в списке коротких ссылок
        f[2] = SHORTENERS.contains(host.toLowerCase()) ? -1 : 1;

        // 4. having_At_Symbol: -1 если @ есть в URL, иначе 1
        f[3] = full.contains("@") ? -1 : 1;

        // 5. double_slash_redirecting: -1 если '//' встречается после позиции 7 (после "https://")
        f[4] = full.indexOf("//", 8) > 0 ? -1 : 1;

        // 6. Prefix_Suffix: -1 если в домене есть дефис ИЛИ IDN-атака, иначе 1
        f[5] = (host.contains("-") || idnAttack) ? -1 : 1;

        // 7. having_Sub_Domain: 1 (≤1 точки), 0 (2 точки), -1 (≥3 точек)
        long dots = host.chars().filter(c -> c == '.').count();
        f[6] = dots <= 1 ? 1 : (dots == 2 ? 0 : -1);

        // 8. SSLfinal_State: 0 (= missing — нужен реальный HTTPS-запрос с валидацией
        //    сертификата). Не используем https как proxy, т.к. фишинговые сайты
        //    тоже массово выпускают Let's Encrypt-сертификаты.
        f[7] = 0;

        // 9. Domain_registeration_length: 0 (нужен WHOIS)
        f[8] = 0;

        // 10. Favicon: 0 (нужен парсинг HTML)
        f[9] = 0;

        // 11. port: -1 если в URL явный нестандартный порт, иначе 1
        int port = uri.getPort();
        f[10] = (port == -1 || port == 80 || port == 443) ? 1 : -1;

        // 12. HTTPS_token: -1 если "https" встречается в host (типичный обман: https-paypal.com)
        f[11] = host.toLowerCase().contains("https") ? -1 : 1;

        // 13. Request_URL: 0 (нужен парсинг HTML)
        f[12] = 0;
        // 14. URL_of_Anchor: -1 если IDN-домен (косвенный признак подделки), иначе 0
        f[13] = idnAttack ? -1 : 0;
        // 15. Links_in_tags: 0 (HTML)
        f[14] = 0;
        // 16. SFH: 0 (HTML)
        f[15] = 0;
        // 17. Submitting_to_email: -1 если в URL/path есть mailto:, иначе 1
        f[16] = full.toLowerCase().contains("mailto:") ? -1 : 1;
        // 18. Abnormal_URL: -1 если IDN-домен (кириллица/Punycode в hostname) или
        //     подозрительный TLD; иначе 0
        boolean suspiciousTld = SUSPICIOUS_TLDS.stream().anyMatch(hostLower::endsWith);
        f[17] = (idnAttack || suspiciousTld) ? -1 : 0;
        // 19. Redirect: 0 (HTTP)
        f[18] = 0;
        // 20. on_mouseover: 0 (JS)
        f[19] = 0;
        // 21. RightClick: 0 (JS)
        f[20] = 0;
        // 22. popUpWidnow: 0 (JS)
        f[21] = 0;
        // 23. Iframe: 0 (HTML)
        f[22] = 0;
        // 24. age_of_domain: 0 (WHOIS)
        f[23] = 0;
        // 25. DNSRecord: 0 (DNS)
        f[24] = 0;
        // 26. web_traffic: 0 (Alexa)
        f[25] = 0;
        // 27. Page_Rank: 0 (PageRank)
        f[26] = 0;
        // 28. Google_Index: 0 (Google API)
        f[27] = 0;
        // 29. Links_pointing_to_page: 0 (внешний API)
        f[28] = 0;
        // 30. Statistical_report: -1 если в hostname/path попадает «подозрительный» паттерн
        f[29] = looksSuspicious(host, path) ? -1 : 1;

        return f;
    }

    /**
     * Эвристика «подозрительности» — расширенный набор:
     * — лексические триггеры (бренды, фишинговые глаголы) на en + ru;
     * — подозрительные TLD (Freenom-зоны и т.п.);
     * — IDN-атаки (non-ASCII или Punycode в hostname).
     */
    private static boolean looksSuspicious(String host, String path) {
        String h = (host + path).toLowerCase();

        // IDN/Punycode
        if (host.chars().anyMatch(c -> c > 127)) return true;
        if (h.contains("xn--")) return true;

        // Подозрительные TLD
        for (String tld : SUSPICIOUS_TLDS) {
            if (host.toLowerCase().endsWith(tld)) return true;
        }

        // Лексические триггеры
        for (String t : EN_TRIGGERS) if (h.contains(t)) return true;
        for (String t : RU_TRIGGERS) if (h.contains(t)) return true;

        return false;
    }
}
