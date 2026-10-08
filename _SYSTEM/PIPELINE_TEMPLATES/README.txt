NUM 4 — PIPELINE_TEMPLATES, версия 3.2 / num_pipeline.py 0.8.0

Шаблоны — только схемы. Их содержимое не является PASS и не является доказательством геометрии.

Последовательность: SOURCES_PASS → BRANCH_PASS → PREALIGN_PASS → GEOMETRY_PASS → DIAGNOSTICS_PASS → ALTERNATIVES_PASS → AUDIT_PASS → VERDICT_RECEIPT.

Обязательный PREALIGN: внешний физический край → проверка эллипса → приведение к кругу → ориентация по общим недиагностическим контурам → машинное подтверждение точного исходного/нормализованного изображения.

prealign_annotations.template.json: рабочие наблюдения края на исходнике и эталоне и независимые наблюдения общих недиагностических ориентиров. Не допускается использование C1–C3 до PREALIGN_PASS; вспомогательные CV-точки не получают автоматического статуса достоверных наблюдений.

prealign.template.json: только результат build-prealign, матрицы, байтовые SHA-256 и provenance. prealign_gate.template.json: только прямой результат validate-prealign по исходным файлам, нормализованному файлу, динамическому артефакту и неизменному GEOMETRY_GATE.json.

geometry_proposal.template.json: C1–C3 и независимые validation points на нормализованной копии, плюс prealign_receipt, normalized_sha256. Машинная validate-geometry должна ЗАНОВО перепроверить prealign, не доверять переданной строке PASS.

Диагностическая зона — только вручную утверждённая пользователем binary diagnostic_region mask полного эталона; её нельзя получать из crop, bounding box или автоматической детекции.

REWORK сохраняется в том же RUN; миграция старого RUN добавляет только PENDING для PREALIGN_PASS, не очищает review_history/счётчик возвратов.

Команды:
  num_pipeline.py suggest-prealign <config> <raw> <reference> --output <annotations>
  num_pipeline.py build-prealign <config> <annotations> <raw> <reference> <normalized.png> <prealign.json> --report <prealign_gate.json>
  num_pipeline.py validate-prealign <config> <prealign.json> <raw> <reference> <normalized.png>
  num_pipeline.py migrate-run-prealign <RUN_DIR>
  num_pipeline.py commit-prealign <RUN_DIR> <config> <prealign.json> <prealign_gate.json> <raw> <reference> <normalized.png>
  num_pipeline.py validate-geometry <config> <proposal> --prealign-report <prealign_gate.json> --prealign-artifact <prealign.json> --raw <raw> --reference <reference> --normalized <normalized.png>