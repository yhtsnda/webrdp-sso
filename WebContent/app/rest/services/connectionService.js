/*
 * Copyright (C) 2015 Glyptodon LLC
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
 * Service for operating on connections via the REST API.
 */
angular.module('rest').factory('connectionService', ['$injector',
        function connectionService($injector) {

    // Required services
    var $http                 = $injector.get('$http');
    var authenticationService = $injector.get('authenticationService');
    var cacheService          = $injector.get('cacheService');
    
    var service = {};
    
    /**
     * Makes a request to the REST API to get a single connection, returning a
     * promise that provides the corresponding @link{Connection} if successful.
     * 
     * @param {String} id The ID of the connection.
     * 
     * @returns {Promise.<Connection>}
     *     A promise which will resolve with a @link{Connection} upon success.
     * 
     * @example
     * 
     * connectionService.getConnection('myConnection').success(function(connection) {
     *     // Do something with the connection
     * });
     */
    service.getConnection = function getConnection(dataSource, id) {

        // Build HTTP parameters set
        var httpParameters = {
            token : authenticationService.getCurrentToken()
        };

        // Retrieve connection
        return $http({
            cache   : cacheService.connections,
            method  : 'GET',
            url     : 'api/data/' + encodeURIComponent(dataSource) + '/connections/' + encodeURIComponent(id),
            params  : httpParameters
        });

    };

    /**
     * Makes a request to the REST API to get the usage history of a single
     * connection, returning a promise that provides the corresponding
     * array of @link{ConnectionHistoryEntry} objects if successful.
     * 
     * @param {String} id
     *     The identifier of the connection.
     * 
     * @returns {Promise.<ConnectionHistoryEntry[]>}
     *     A promise which will resolve with an array of
     *     @link{ConnectionHistoryEntry} objects upon success.
     */
    service.getConnectionHistory = function getConnectionHistory(dataSource, id) {

        // Build HTTP parameters set
        var httpParameters = {
            token : authenticationService.getCurrentToken()
        };

        // Retrieve connection history
        return $http({
            method  : 'GET',
            url     : 'api/data/' + encodeURIComponent(dataSource) + '/connections/' + encodeURIComponent(id) + '/history',
            params  : httpParameters
        });
 
    };

    /**
     * Makes a request to the REST API to get the parameters of a single
     * connection, returning a promise that provides the corresponding
     * map of parameter name/value pairs if successful.
     * 
     * @param {String} id
     *     The identifier of the connection.
     * 
     * @returns {Promise.<Object.<String, String>>}
     *     A promise which will resolve with an map of parameter name/value
     *     pairs upon success.
     */
    service.getConnectionParameters = function getConnectionParameters(dataSource, id) {

        // Build HTTP parameters set
        var httpParameters = {
            token : authenticationService.getCurrentToken()
        };

        // Retrieve connection parameters
        return $http({
            cache   : cacheService.connections,
            method  : 'GET',
            url     : 'api/data/' + encodeURIComponent(dataSource) + '/connections/' + encodeURIComponent(id) + '/parameters',
            params  : httpParameters
        });
 
    };

    /**
     * Makes a request to the REST API to save a connection, returning a
     * promise that can be used for processing the results of the call. If the
     * connection is new, and thus does not yet have an associated identifier,
     * the identifier will be automatically set in the provided connection
     * upon success.
     * 
     * @param {Connection} connection The connection to update.
     *                          
     * @returns {Promise}
     *     A promise for the HTTP call which will succeed if and only if the
     *     save operation is successful.
     */
    service.saveConnection = function saveConnection(dataSource, connection) {
        
        // Build HTTP parameters set
        var httpParameters = {
            token : authenticationService.getCurrentToken()
        };

        // If connection is new, add it and set the identifier automatically
        if (!connection.identifier) {
            return $http({
                method  : 'POST',
                url     : 'api/data/' + encodeURIComponent(dataSource) + '/connections',
                params  : httpParameters,
                data    : connection
            })

            // Set the identifier on the new connection and clear the cache
            .success(function connectionCreated(newConnection){
                connection.identifier = newConnection.identifier;
                cacheService.connections.removeAll();
            });
        }

        // Otherwise, update the existing connection
        else {
            return $http({
                method  : 'PUT',
                url     : 'api/data/' + encodeURIComponent(dataSource) + '/connections/' + encodeURIComponent(connection.identifier),
                params  : httpParameters,
                data    : connection
            })
            
            // Clear the cache
            .success(function connectionUpdated(){
                cacheService.connections.removeAll();
            });
        }

    };
    
    /**
     * Makes a request to the REST API to delete a connection,
     * returning a promise that can be used for processing the results of the call.
     * 
     * @param {Connection} connection The connection to delete.
     *                          
     * @returns {Promise}
     *     A promise for the HTTP call which will succeed if and only if the
     *     delete operation is successful.
     */
    service.deleteConnection = function deleteConnection(dataSource, connection) {

        // Build HTTP parameters set
        var httpParameters = {
            token : authenticationService.getCurrentToken()
        };

        // Delete connection
        return $http({
            method  : 'DELETE',
            url     : 'api/data/' + encodeURIComponent(dataSource) + '/connections/' + encodeURIComponent(connection.identifier),
            params  : httpParameters
        })

        // Clear the cache
        .success(function connectionDeleted(){
            cacheService.connections.removeAll();
        });

    };
    
    return service;
}]);
