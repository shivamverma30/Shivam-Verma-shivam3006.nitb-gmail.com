import React from 'react';

// A permission-gated action. Present-or-absent, never disabled (UI-INVENTORY.md §1).
//
// The `permissions` object is the server's resolved set for the relevant scope (org
// or device). The element renders ONLY when permissions[permission].effect === 'allow'.
// When rendered it carries data-permission and data-state="unlocked".
//
// There is NO role-to-permission table here. The decision comes entirely from the
// server's resolved permissions. This is the architecture the ui.spec.js "vanishes when
// the server withdraws the permission" test verifies.

export function isAllowed(permissions, permission) {
  return permissions?.[permission]?.effect === 'allow';
}

export default function Action({ permissions, permission, testId, onClick, children, as = 'button', className = 'btn small' }) {
  if (!isAllowed(permissions, permission)) return null;

  const Tag = as;
  return (
    <Tag
      data-testid={testId}
      data-permission={permission}
      data-state="unlocked"
      className={className}
      onClick={onClick}
    >
      {children}
    </Tag>
  );
}
