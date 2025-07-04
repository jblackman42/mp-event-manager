'use client';

import { useSession } from './SessionProvider';

export function UserProfile() {
  const session = useSession();

  if (!session) {
    return (
      <div className="p-4 bg-gray-100 rounded">
        <p>Not logged in</p>
      </div>
    );
  }

  return (
    <div className="p-4 bg-white border rounded shadow">
      <h2 className="text-gray-600 text-xl font-bold mb-2">Welcome, {session.userid}</h2>
      <p className="text-gray-600">Roles: {session.user_roles}</p>
      <p className="text-gray-600">Groups: {session.user_groups}</p>
    </div>
  );
} 