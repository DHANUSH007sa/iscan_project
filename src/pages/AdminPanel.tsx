import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowLeft, Shield, Trash2, UserCog, Users } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useAuth } from "@/contexts/auth-context";
import { useToast } from "@/hooks/use-toast";
import Logo from "@/components/Logo";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";

interface User {
  id: number;
  firstName: string;
  lastName: string;
  email: string;
  dateOfBirth: string;
  createdAt: number;
  isAdmin: boolean;
}

const AdminPanel: React.FC = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [deleteUserId, setDeleteUserId] = useState<number | null>(null);
  const [adminUser, setAdminUser] = useState<any>(null);

  useEffect(() => {
    // Check if admin is logged in via session storage
    const adminData = sessionStorage.getItem("adminUser");
    if (!adminData) {
      toast({
        title: "Access Denied",
        description: "Please login as administrator",
        variant: "destructive",
      });
      navigate("/admin");
      return;
    }

    try {
      const admin = JSON.parse(adminData);
      if (!admin.isAdmin) {
        toast({
          title: "Access Denied",
          description: "You must be an administrator to access this page",
          variant: "destructive",
        });
        navigate("/admin");
        return;
      }
      setAdminUser(admin);
      fetchUsers();
    } catch (error) {
      navigate("/admin");
    }
  }, [navigate, toast]);

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/admin/users");
      if (res.ok) {
        const data = await res.json();
        setUsers(data.users || []);
      } else {
        throw new Error("Failed to fetch users");
      }
    } catch (error) {
      console.error("Error fetching users:", error);
      toast({
        title: "Error",
        description: "Failed to load users",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteUser = async (userId: number) => {
    try {
      const res = await fetch(`/api/admin/users/${userId}`, {
        method: "DELETE",
      });

      if (res.ok) {
        toast({
          title: "Success",
          description: "User deleted successfully",
        });
        fetchUsers(); // Refresh the list
      } else {
        const data = await res.json();
        throw new Error(data.error || "Failed to delete user");
      }
    } catch (error: any) {
      console.error("Error deleting user:", error);
      toast({
        title: "Error",
        description: error.message || "Failed to delete user",
        variant: "destructive",
      });
    } finally {
      setDeleteUserId(null);
    }
  };

  const handleToggleAdmin = async (userId: number) => {
    try {
      const res = await fetch(`/api/admin/users/${userId}/toggle-admin`, {
        method: "POST",
      });

      if (res.ok) {
        toast({
          title: "Success",
          description: "Admin status updated successfully",
        });
        fetchUsers(); // Refresh the list
      } else {
        const data = await res.json();
        throw new Error(data.error || "Failed to update admin status");
      }
    } catch (error: any) {
      console.error("Error updating admin status:", error);
      toast({
        title: "Error",
        description: error.message || "Failed to update admin status",
        variant: "destructive",
      });
    }
  };

  const formatDate = (timestamp: number) => {
    return new Date(timestamp * 1000).toLocaleDateString();
  };

  const handleAdminLogout = () => {
    sessionStorage.removeItem("adminUser");
    toast({
      title: "Logged Out",
      description: "You have been logged out from admin panel",
    });
    navigate("/admin");
  };

  if (!adminUser) {
    return null;
  }

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b bg-card/50 backdrop-blur-xl">
        <div className="flex items-center justify-between px-6 py-4">
          <div className="flex items-center space-x-4">
            <Logo size="sm" showText={true} variant="light" />
          </div>
          <div className="flex items-center gap-4">
            <span className="text-sm text-muted-foreground">
              Logged in as: <span className="font-semibold">{adminUser.firstName} {adminUser.lastName}</span>
            </span>
            <Button variant="outline" size="sm" onClick={handleAdminLogout}>
              Logout
            </Button>
          </div>
        </div>
      </header>

      <div className="p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-3xl font-bold">User Management</h2>
            <p className="text-muted-foreground">Manage registered users and their permissions</p>
          </div>
          <div className="flex items-center gap-2">
            <Users className="h-5 w-5 text-muted-foreground" />
            <span className="text-2xl font-bold">{users.length}</span>
            <span className="text-muted-foreground">Total Users</span>
          </div>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Registered Users</CardTitle>
            <CardDescription>View and manage all registered users</CardDescription>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="text-center py-8">Loading users...</div>
            ) : users.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">No users found</div>
            ) : (
              <div className="space-y-4">
                {users.map((u) => (
                  <div
                    key={u.id}
                    className="flex items-center justify-between p-4 border rounded-lg hover:bg-muted/50 transition-colors"
                  >
                    <div className="flex-1">
                      <div className="flex items-center gap-3">
                        <h3 className="font-semibold text-lg">
                          {u.firstName} {u.lastName}
                        </h3>
                        {u.isAdmin && (
                          <Badge variant="default" className="bg-blue-600">
                            <Shield className="h-3 w-3 mr-1" />
                            Admin
                          </Badge>
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground">{u.email}</p>
                      <p className="text-xs text-muted-foreground mt-1">
                        Joined: {formatDate(u.createdAt)} • DOB: {u.dateOfBirth}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      {u.id !== 1 && (
                        <>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleToggleAdmin(u.id)}
                            title={u.isAdmin ? "Remove admin privileges" : "Grant admin privileges"}
                          >
                            <UserCog className="h-4 w-4 mr-2" />
                            {u.isAdmin ? "Remove Admin" : "Make Admin"}
                          </Button>
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={() => setDeleteUserId(u.id)}
                            title="Delete user"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </>
                      )}
                      {u.id === 1 && (
                        <Badge variant="secondary" className="text-xs">
                          Main Admin (Protected)
                        </Badge>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={deleteUserId !== null} onOpenChange={() => setDeleteUserId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Are you sure?</AlertDialogTitle>
            <AlertDialogDescription>
              This action cannot be undone. This will permanently delete the user account and all
              associated data.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => deleteUserId && handleDeleteUser(deleteUserId)}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Delete User
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
};

export default AdminPanel;
