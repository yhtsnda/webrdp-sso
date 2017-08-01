/*
 * Copyright (C) 2014 Glyptodon LLC
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/**
 * Service for operating on user permissions via the REST API.
 */
angular.module('rest').factory('permissionService', ['$injector',
        function permissionService($injector) {

    // Required services
    var $http                 = $injector.get('$http');
    var $q                    = $injector.get('$q');
    var authenticationService = $injector.get('authenticationService');
    var cacheService          = $injector.get('cacheService');
    
    // Required types
    var PermissionPatch = $injector.get('PermissionPatch');

    var service = {};

    /**
     * Makes a request to the REST API to get the list of permissions for a
     * given user, returning a promise that provides an array of
     * @link{Permission} objects if successful.
     * 
     * @param {String} dataSource
     *     The unique identifier of the data source containing the user whose
     *     permissions should be retrieved. This identifier corresponds to an
     *     AuthenticationProvider within the Guacamole web application.
     *
     * @param {String} userID
     *     The ID of the user to retrieve the permissions for.
     *                          
     * @returns {Promise.<PermissionSet>}
     *     A promise which will resolve with a @link{PermissionSet} upon
     *     success.
     */
    service.getPermissions = function getPermissions(dataSource, userID) {

        // Build HTTP parameters set
        var httpParameters = {
            token : authenticationService.getCurrentToken()
        };

        // Retrieve user permissions
        return $http({
            cache   : cacheService.users,
            method  : 'GET',
            url     : 'api/data/' + encodeURIComponent(dataSource) + '/users/' + encodeURIComponent(userID) + '/permissions',
            params  : httpParameters
        });

    };

    /**
     * Makes a request to the REST API to add permissions for a given user,
     * returning a promise that can be used for processing the results of the
     * call.
     * 
     * @param {String} dataSource
     *     The unique identifier of the data source containing the user whose
     *     permissions should be modified. This identifier corresponds to an
     *     AuthenticationProvider within the Guacamole web application.
     *
     * @param {String} userID
     *     The ID of the user to modify the permissions of.
     *                          
     * @param {PermissionSet} permissions
     *     The set of permissions to add.
     *                          
     * @returns {Promise}
     *     A promise for the HTTP call which will succeed if and only if the
     *     add operation is successful.
     */
    service.addPermissions = function addPermissions(dataSource, userID, permissions) {
        return service.patchPermissions(dataSource, userID, permissions, null);
    };
    
    /**
     * Makes a request to the REST API to remove permissions for a given user,
     * returning a promise that can be used for processing the results of the
     * call.
     * 
     * @param {String} dataSource
     *     The unique identifier of the data source containing the user whose
     *     permissions should be modified. This identifier corresponds to an
     *     AuthenticationProvider within the Guacamole web application.
     *
     * @param {String} userID
     *     The ID of the user to modify the permissions of.
     *                          
     * @param {PermissionSet} permissions
     *     The set of permissions to remove.
     *                          
     * @returns {Promise}
     *     A promise for the HTTP call which will succeed if and only if the
     *     remove operation is successful.
     */
    service.removePermissions = function removePermissions(dataSource, userID, permissions) {
        return service.patchPermissions(dataSource, userID, null, permissions);
    };

    /**
     * Adds patches for modifying the permissions associated with specific
     * objects to the given array of patches.
     *
     * @param {PermissionPatch[]} patch
     *     The array of patches to add new patches to.
     *
     * @param {String} operation
     *     The operation to specify within each of the patches. Valid values
     *     for this are defined within PermissionPatch.Operation.
     *     
     * @param {String} path
     *     The path of the permissions being patched. The path is a JSON path
     *     describing the position of the permissions within a PermissionSet.
     *
     * @param {Object.<String, String[]>} permissions
     *     A map of object identifiers to arrays of permission type strings,
     *     where each type string is a value from
     *     PermissionSet.ObjectPermissionType.
     */
    var addObjectPatchOperations = function addObjectPatchOperations(patch, operation, path, permissions) {

        // Add object permission operations to patch
        for (var identifier in permissions) {
            permissions[identifier].forEach(function addObjectPatch(type) {
                patch.push({
                    op    : operation,
                    path  : path + "/" + identifier,
                    value : type
                });
            });
        }

    };

    /**
     * Adds patches for modifying any permission that can be stored within a
     * @link{PermissionSet}.
     * 
     * @param {PermissionPatch[]} patch
     *     The array of patches to add new patches to.
     *
     * @param {String} operation
     *     The operation to specify within each of the patches. Valid values
     *     for this are defined within PermissionPatch.Operation.
     *
     * @param {PermissionSet} permissions
     *     The set of permissions for which patches should be added.
     */
    var addPatchOperations = function addPatchOperations(patch, operation, permissions) {

        // Add connection permission operations to patch
        addObjectPatchOperations(patch, operation, "/connectionPermissions",
            permissions.connectionPermissions);

        // Add connection group permission operations to patch
        addObjectPatchOperations(patch, operation, "/connectionGroupPermissions",
            permissions.connectionGroupPermissions);

        // Add active connection permission operations to patch
        addObjectPatchOperations(patch, operation, "/activeConnectionPermissions",
            permissions.activeConnectionPermissions);

        // Add user permission operations to patch
        addObjectPatchOperations(patch, operation, "/userPermissions",
            permissions.userPermissions);

        // Add system operations to patch
        permissions.systemPermissions.forEach(function addSystemPatch(type) {
            patch.push({
                op    : operation,
                path  : "/systemPermissions",
                value : type
            });
        });

    };
            
    /**
     * Makes a request to the REST API to modify the permissions for a given
     * user, returning a promise that can be used for processing the results of
     * the call.
     * 
     * @param {String} dataSource
     *     The unique identifier of the data source containing the user whose
     *     permissions should be modified. This identifier corresponds to an
     *     AuthenticationProvider within the Guacamole web application.
     *
     * @param {String} userID
     *     The ID of the user to modify the permissions of.
     *                          
     * @param {PermissionSet} [permissionsToAdd]
     *     The set of permissions to add, if any.
     *
     * @param {PermissionSet} [permissionsToRemove]
     *     The set of permissions to remove, if any.
     *                          
     * @returns {Promise}
     *     A promise for the HTTP call which will succeed if and only if the
     *     patch operation is successful.
     */
    service.patchPermissions = function patchPermissions(dataSource, userID, permissionsToAdd, permissionsToRemove) {

        var permissionPatch = [];
        
        // Build HTTP parameters set
        var httpParameters = {
            token : authenticationService.getCurrentToken()
        };

        // Add all the add operations to the patch
        addPatchOperations(permissionPatch, PermissionPatch.Operation.ADD, permissionsToAdd);

        // Add all the remove operations to the patch
        addPatchOperations(permissionPatch, PermissionPatch.Operation.REMOVE, permissionsToRemove);

        // Patch user permissions
        return $http({
            method  : 'PATCH', 
            url     : 'api/data/' + encodeURIComponent(dataSource) + '/users/' + encodeURIComponent(userID) + '/permissions',
            params  : httpParameters,
            data    : permissionPatch
        })
        
        // Clear the cache
        .success(function permissionsPatched(){
            cacheService.users.removeAll();
        });
    };
    
    return service;

}]);
