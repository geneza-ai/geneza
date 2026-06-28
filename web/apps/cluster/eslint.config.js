import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      globals: globals.browser,
    },
  },
  {
    // shadcn/ui components export `*Variants` helpers alongside the component,
    // and a few modules co-locate a hook/context with their provider. These
    // are intentional and only affect dev fast-refresh.
    files: [
      'src/components/ui/**/*.{ts,tsx}',
      'src/components/theme-provider.tsx',
    ],
    rules: {
      'react-refresh/only-export-components': 'off',
    },
  },
])
