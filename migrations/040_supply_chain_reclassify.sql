-- 040_supply_chain_reclassify.sql — one-shot fix for legacy supply-chain
-- rows mis-tagged as "tampered".
--
-- Pre-Sprint-7.1 every cosign verify failure (binary missing, registry
-- unreachable, image unsigned) was stored with status='tampered' — a
-- security event semantic. The dashboard then displayed dozens of
-- alarming TAMPERED rows that were actually ops or dev-environment
-- issues. The handler is now fixed (classifyVerifyFailure); this
-- migration cleans up the historical data so existing rows display
-- correctly without re-running verify.
--
-- We keep the row's `reason` column intact so the audit story is
-- preserved — only `status` is updated. Rows whose reason doesn't
-- match any recognised pattern are left as 'tampered' so a real
-- security event isn't downgraded.

UPDATE supply_chain_signatures
   SET status = 'unavailable'
 WHERE status = 'tampered'
   AND (
        COALESCE(reason,'') ILIKE '%executable file not found%'
     OR COALESCE(reason,'') ILIKE '%no such file or directory%'
     OR COALESCE(reason,'') ILIKE '%permission denied%'
   );

UPDATE supply_chain_signatures
   SET status = 'unsigned'
 WHERE status = 'tampered'
   AND (
        COALESCE(reason,'') ILIKE '%no signatures found%'
     OR COALESCE(reason,'') ILIKE '%no matching signatures%'
   );

UPDATE supply_chain_signatures
   SET status = 'not_found'
 WHERE status = 'tampered'
   AND (
        COALESCE(reason,'') ILIKE '%manifest unknown%'
     OR COALESCE(reason,'') ILIKE '%manifest_unknown%'
     OR COALESCE(reason,'') ILIKE '%name unknown%'
     OR COALESCE(reason,'') ILIKE '%name_unknown%'
     OR COALESCE(reason,'') ILIKE '%no such host%'
     OR COALESCE(reason,'') ILIKE '%connection refused%'
     OR COALESCE(reason,'') ILIKE '%dial tcp%'
   );

-- Anything still tagged 'tampered' after this is either a real signature
-- mismatch (the actual security event) or a row whose reason text we
-- don't recognise — in either case the conservative call is to leave
-- it tampered so a security analyst can review.
