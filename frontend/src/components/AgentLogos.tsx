/** Monochrome marks for footer credits (inherit `currentColor`). */

export function GrokBuildLogo({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 34 33"
      width="14"
      height="14"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      <path
        fill="currentColor"
        d="M13.237 21.041 24.319 12.851c.543-.402 1.32-.245 1.578.379 1.363 3.289.754 7.242-1.957 9.955-2.71 2.714-6.482 3.309-9.929 1.954l-3.766 1.745c5.401 3.697 11.96 2.783 16.059-1.324 3.251-3.255 4.258-7.692 3.316-11.693.009.009.017.017.026.026 1.365-5.878 3.066-8.227 6.55-13.031.083-.114.165-.228.248-.345L29.11 5.091v-.014L13.234 21.044"
      />
      <path
        fill="currentColor"
        d="M10.95 23.031c-3.877-3.708-3.208-9.446.1-12.755 2.446-2.449 6.454-3.448 9.952-1.979l3.758-1.737c-.677-.49-1.545-1.017-2.54-1.387-4.5-1.854-9.887-.931-13.545 2.728-3.518 3.523-4.625 8.939-2.725 13.561 1.42 3.454-.907 5.898-3.25 8.364C1.868 30.7 1.035 31.575.364 32.5l10.583-9.466"
      />
    </svg>
  )
}

export function OpenCodeLogo({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      width="14"
      height="14"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      <path
        fill="currentColor"
        fillRule="evenodd"
        clipRule="evenodd"
        d="M20 21H4V3h16v18ZM16 7H8v12h8V7Z"
      />
    </svg>
  )
}
