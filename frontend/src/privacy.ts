import type { PrivacyEntity } from './api'

export type MaskingResult = {
    maskedText: string
    placeholderToOriginal: Record<string, string>
}

export function maskEntitiesLocally(
    originalText: string,
    entities: PrivacyEntity[],
): MaskingResult {
    // Array.from counts Unicode code points, matching the recommended API offsets.
    const originalCharacters = Array.from(originalText)

    const validEntities = entities
        .filter(
            (entity) =>
                Number.isInteger(entity.start) &&
                Number.isInteger(entity.end) &&
                entity.start >= 0 &&
                entity.end > entity.start &&
                entity.end <= originalCharacters.length,
        )
        .sort((a, b) => a.start - b.start || b.end - a.end)

    // Ignore overlapping spans so the same text is not masked twice.
    const nonOverlappingEntities: PrivacyEntity[] = []
    let lastEnd = -1

    for (const entity of validEntities) {
        if (entity.start < lastEnd) continue
        nonOverlappingEntities.push(entity)
        lastEnd = entity.end
    }

    const placeholderToOriginal: Record<string, string> = {}
    const counts: Record<string, number> = {}
    const maskedCharacters: string[] = [...originalCharacters]

    // Replace from right to left so earlier positions stay valid.
    for (const entity of [...nonOverlappingEntities].reverse()) {
        const originalValue = originalCharacters
            .slice(entity.start, entity.end)
            .join('')

        counts[entity.type] = (counts[entity.type] ?? 0) + 1
        const placeholder = `[${entity.type}_${counts[entity.type]}]`

        placeholderToOriginal[placeholder] = originalValue
        maskedCharacters.splice(
            entity.start,
            entity.end - entity.start,
            placeholder,
        )
    }

    return {
        maskedText: maskedCharacters.join(''),
        placeholderToOriginal,
    }
}