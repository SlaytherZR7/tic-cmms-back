import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

import * as bcrypt from 'bcrypt';

import { User } from './entities/user.entity';
import { LoginUserDto, CreateUserDto } from './dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { Response } from 'express';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,

    private readonly jwtService: JwtService,
  ) {}

  async create(createUserDto: CreateUserDto, @Res() res: Response) {
    try {
      const { password, ...userData } = createUserDto;

      const user = this.userRepository.create({
        ...userData,
        password: bcrypt.hashSync(password, 10),
      });

      await this.userRepository.save(user);
      delete user.password;

      const token = this.getJwtToken({ id: user.id });

      res
        .cookie('session', token, {
          httpOnly: true,
          secure: false, // True in production
          expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7),
        })
        .send({ ...user, token });
    } catch (error) {
      this.handleDBErrors(error);
    }
  }

  async login(loginUserDto: LoginUserDto, @Res() res: Response) {
    const { password, email } = loginUserDto;

    const user = await this.userRepository.findOne({
      where: { email },
      select: { email: true, password: true, id: true },
    });

    if (!user || !bcrypt.compareSync(password, user.password))
      throw new UnauthorizedException('Credentials are not valid');

    const token = this.getJwtToken({ id: user.id });

    res
      .cookie('session', token, {
        httpOnly: true,
        secure: false, // True in production
        expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7),
      })
      .send({ ...user, token });
  }

  async logout(@Res() res: Response) {
    res.clearCookie('session').send();
  }

  async checkAuthStatus(user: User, @Res() res: Response) {
    const token = this.getJwtToken({ id: user.id });

    res
      .cookie('session', token, {
        httpOnly: true,
        secure: false, // True in production
        expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7),
      })
      .send({ ...user, token });
  }

  private getJwtToken(payload: JwtPayload) {
    const token = this.jwtService.sign(payload);
    return token;
  }

  private handleDBErrors(error: any): never {
    if (error.code === '23505') throw new BadRequestException(error.detail);

    console.log(error);

    throw new InternalServerErrorException('Please check server logs');
  }
}
