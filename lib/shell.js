/*
 * Copyright (c) 2020-2023 LG Electronics Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

const async = require('async'),
    npmlog = require('npmlog'),
    sessionLib = require('./session'),
    errHndl = require('./base/error-handler'),
    novacom = require('./base/novacom');

(function() {
    const log = npmlog;

    log.heading = 'logger';
    log.level = 'warn';

    const shell = {
        log: log,

        remoteRun: function(options, runCommand, next) {
            log.info('shell#remoteRun()');
            async.series([
                function(next) {
                    makeSession(options, next);
                },
                function(next) {
                    if (options && options.display) {
                        sessionLib.getSessionList(options, next);
                    } else {
                        next();
                    }
                },
                function(next) {
                    if (options && options.display && !options.sessionCall) {
                        setImmediate(next, errHndl.getErrMsg("NOT_SUPPORT_SESSION"), {});
                    }
                    next();
                },
                function(next) {
                    if (options.sessionId) {
                        if (options.session.getDevice().username !== 'root') {
                            return setImmediate(next, errHndl.getErrMsg("NEED_ROOT_PERMISSION", "connect user session"));
                        }

                        // -l : make the shell a login shell, -c : command
                        runCommand = `su ${options.sessionId} -l -c '${runCommand}'`;
                    } else {
                        // Source the profile only when it exists and is readable
                        // (jailed dev-mode shells may not have access to it), and
                        // use POSIX '.' since the device shell lacks 'source'.
                        runCommand = "[ -r /etc/profile ] && . /etc/profile; " + runCommand;
                    }

                    log.info("shell#remoteRun()", "cmd :", runCommand);
                    options.session.run(runCommand, process.stdin, _onData, _onErr, next);

                    function _onData(data) {
                        const str = (Buffer.isBuffer(data)) ? data.toString() : data;
                        next(null, str.trim());
                    }

                    function _onErr(err) {
                        next(errHndl.getErrMsg(err), null);
                    }

                }
            ], function(err, results) {
                next(err, {msg: results[3]});
            });
        },

        shell: function(options, next) {
            log.info('shell#shell()');
            const _ssh = function(session, finish) {
                async.series([
                    function(next) {
                        makeSession(options, next);
                    },
                    function(next) {
                        // Interactive shell over system ssh (ssh -tt, terminal
                        // wired straight through, which also handles window size).
                        let cmd = null;
                        if (options.sessionId) {
                            if (options.session.getDevice().username !== 'root') {
                                return setImmediate(next, errHndl.getErrMsg("NEED_ROOT_PERMISSION", "connect user session"));
                            }
                            cmd = `su ${options.sessionId} -l`;
                        }
                        session.interactiveShell(cmd, function(err) {
                            session.end();
                            next(err);
                        });
                    }
                ], function(err, result) {
                    let flag_reboot = false;
                    if (result.indexOf("id") > 0) {
                        flag_reboot = true;
                    }
                    finish(err,flag_reboot);
                });
            };

            async.series([
                function(next) {
                    makeSession(options, next);
                },
                function(next) {
                    if (options && options.display) {
                        sessionLib.getSessionList(options, next);
                    } else {
                        next();
                    }
                },
                function(next) {
                    if (options && options.display && !options.sessionCall) {
                        setImmediate(next, errHndl.getErrMsg("NOT_SUPPORT_SESSION"), {});
                    }
                    next();
                },
                function(next) {
                    _ssh(options.session, next);
                }
            ], function(err) {
                // Print "Connection to IP closed." message as like ssh prompt
                next(err, {msg: "Connection to " + options.session.target.host + " closed."});
            });
        }
    };

    function makeSession(options, next){
        options.nReplies = 1; // -n 1
        if (!options.session) {
            log.info("shell#makeSession()", "need to make new session");
            const printTarget = false;
            options.session = new novacom.Session(options.device, printTarget, next);
        } else {
            log.info("shell#makeSession()", "already exist session");
            next();
        }
    }

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = shell;
    }
}());
