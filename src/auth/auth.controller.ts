import { Controller, Get, Post, Body, HttpCode, Res } from '@nestjs/common';

import { AuthService } from './auth.service';
import { GetUser, Auth } from './decorators';

import { CreateUserDto, LoginUserDto } from './dto';
import { User } from './entities/user.entity';
import { Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  createUser(@Body() createUserDto: CreateUserDto, @Res() res: Response) {
    return this.authService.create(createUserDto, res);
  }

  @Post('login')
  @HttpCode(200)
  loginUser(@Body() loginUserDto: LoginUserDto, @Res() res: Response) {
    return this.authService.login(loginUserDto, res);
  }

  @Post('logout')
  @Auth()
  logout(@Res() res: Response) {
    return this.authService.logout(res);
  }

  @Get('check-status')
  @Auth()
  checkAuthStatus(@GetUser() user: User, @Res() res: Response) {
    return this.authService.checkAuthStatus(user, res);
  }
}
