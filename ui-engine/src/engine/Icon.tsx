const shapes = {
  settings: (
    <>
      <path d="m9 3 1 2h4l1-2 3 2-1 2 2 3 2 1v3l-2 1-2 3 1 2-3 1-1-2h-4l-1 2-3-1 1-2-2-3-2-1v-3l2-1 2-3-1-2z" />
      <circle cx="12" cy="12" r="3" />
    </>
  ),
  database: (
    <>
      <ellipse cx="12" cy="5" rx="8" ry="3" />
      <path d="M4 5v14c0 4 16 4 16 0V5M4 12c0 4 16 4 16 0" />
    </>
  ),
  refresh: (
    <>
      <path d="M20 7v5h-5M4 17v-5h5M5 8a8 8 0 0 1 14-2l1 6M4 12l1 6a8 8 0 0 0 14-2" />
    </>
  ),
  bell: (
    <>
      <path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4" />
    </>
  ),
  page: (
    <>
      <path d="M14 3H5v18h14V8M14 3v5h5" />
      <path d="m10 15 8-8 3 3-8 8-4 1z" />
    </>
  ),
  folder: (
    <>
      <path d="M3 6h7l2 3h9v12H3z" />
      <path d="M12 12v6m-3-3h6" />
    </>
  ),
  search: (
    <>
      <circle cx="10" cy="10" r="6" />
      <path d="m15 15 6 6" />
    </>
  ),
  home: (
    <>
      <path d="m3 10 9-7 9 7M5 9v12h14V9M9 21v-8h6v8" />
    </>
  ),
  sidebar: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="M9 4v16" />
    </>
  ),
  plus: <path d="M12 4v16M4 12h16" />,
  code: <path d="m8 6-6 6 6 6m8-12 6 6-6 6m-3-15-2 18" />,
  preview: (
    <>
      <path d="M12 5c-3-2-6-2-10-1v15c4-1 7-1 10 1 3-2 6-2 10-1V4c-4-1-7-1-10 1zM12 5v15" />
    </>
  ),
  save: <path d="m4 12 5 5L20 6" />,
  menu: (
    <>
      <circle cx="12" cy="5" r="1" />
      <circle cx="12" cy="12" r="1" />
      <circle cx="12" cy="19" r="1" />
    </>
  ),
};
export type IconName = keyof typeof shapes;
export function Icon({ name }: { name: IconName }) {
  return (
    <svg
      className="app-icon"
      aria-hidden="true"
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      {shapes[name]}
    </svg>
  );
}
