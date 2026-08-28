export const ASSET_NAME_MIN_LENGTH = 1;
export const ASSET_NAME_MAX_LENGTH = 200;
export const ASSET_DESCRIPTION_MAX_LENGTH = 2000;
export const ASSET_DEPLOYMENT_CONTEXT_MAX_LENGTH = 2000;
export const ASSET_REPOSITORY_URL_MAX_LENGTH = 2048;

export const ASSET_TAG_MIN_LENGTH = 1;
export const ASSET_TAG_MAX_LENGTH = 64;
export const ASSET_TAG_MAX_COUNT = 20;

export const ASSET_IDENTIFIER_NAMESPACE_MIN_LENGTH = 1;
export const ASSET_IDENTIFIER_NAMESPACE_MAX_LENGTH = 64;
export const ASSET_IDENTIFIER_VALUE_MIN_LENGTH = 1;
export const ASSET_IDENTIFIER_VALUE_MAX_LENGTH = 256;
export const ASSET_IDENTIFIER_MAX_COUNT = 20;

export const ASSET_OWNER_MAX_COUNT = 20;

export const ASSET_NAME_PREFIX_MIN_LENGTH = 2;
export const ASSET_LIST_DEFAULT_LIMIT = 20;
export const ASSET_LIST_MIN_LIMIT = 1;
export const ASSET_LIST_MAX_LIMIT = 100;

export const ASSET_LIST_CURSOR_VERSION = 1;

export const ASSET_SLUG_SHAPE = /^[a-z0-9]+(-[a-z0-9]+)*$/;

/** Raw HTTP/text cap before normalization. Not a substitute for field maxima. */
export const ASSET_RAW_TEXT_MAX_LENGTH = 4096;

export const DEFAULT_BUSINESS_CRITICALITY = 'unspecified' as const;
export const DEFAULT_INTERNET_EXPOSURE = 'unknown' as const;
export const DEFAULT_DATA_CLASSIFICATION = 'unspecified' as const;
export const DEFAULT_ASSET_LIFECYCLE_LIST_FILTER = 'active' as const;
