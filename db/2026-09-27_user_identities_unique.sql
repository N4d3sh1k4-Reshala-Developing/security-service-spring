-- Уникальность social-identity: один provider_user_id не может принадлежать двум пользователям.
-- Hibernate (ddl-auto: update) не добавляет unique-ограничения к существующей таблице, применять вручную.
--
-- 1) Проверить дубли (если строки есть — сначала решить, какие оставить):
SELECT provider, provider_user_id, COUNT(*) AS duplicates, MIN(user_id) AS keep_user_id
FROM user_identities
GROUP BY provider, provider_user_id
HAVING COUNT(*) > 1;

-- 2) Удалить дубли, оставив запись с минимальным user_id:
DELETE FROM user_identities a
USING user_identities b
WHERE a.provider = b.provider
  AND a.provider_user_id = b.provider_user_id
  AND a.user_id > b.user_id;

-- 3) Добавить ограничение:
CREATE UNIQUE INDEX IF NOT EXISTS uk_user_identities_provider_user
    ON user_identities (provider, provider_user_id);
