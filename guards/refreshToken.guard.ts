import {
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JsonWebTokenError } from '@nestjs/jwt';
import { AuthGuard } from '@nestjs/passport';
import { InjectRepository } from '@nestjs/typeorm';
import { Request, Response } from 'express';
import { JwtAuth } from 'src/auth/entities/jwt-auth.entity';
import { User } from 'src/user/entities/user.entity';
import { Repository } from 'typeorm';

@Injectable()
export class RefreshTokenGuard extends AuthGuard('refresh-jwt') {
  constructor(
    @InjectRepository(JwtAuth)
    private readonly jwtAuthRepo: Repository<JwtAuth>,
  ) {
    super();
  }
  handleRequest(
    err: any,
    user: User,
    info: any,
    context: ExecutionContext,
  ): any {
    const request = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse<Response>();
    const authHeader = request.headers['authorization'];

    function clearCookieAndThrowError() {
      response.clearCookie('AccessToken');
      response.clearCookie('RefreshToken');
      throw new UnauthorizedException();
    }

    let token: string | null = null;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
    } else return clearCookieAndThrowError();

    if (!user || err) {
      return clearCookieAndThrowError();
    }
    if (info instanceof JsonWebTokenError) {
      this.jwtAuthRepo.delete({ Refresh: token });
      return clearCookieAndThrowError();
    }
    return user;
  }
}
