package com.auth.aws.token;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
@RestController
@RequestMapping(path = "/rest/users")
public class UserController {
    @Autowired
    UsersService usersService;
    @PostMapping(path = "/login")
    public ResponseEntity<Object> login(@RequestBody UserLoginRequestPayload userLoginRequestPayload) throws Exception {
        try {
            UserLoginResponsePayload userLoginResponsePayload = usersService.processLogin(userLoginRequestPayload);
            return new ResponseEntity<>(userLoginResponsePayload, HttpStatus.OK);
        } catch (Exception exception) {
            return new ResponseEntity<>(exception.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}