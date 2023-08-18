import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from '../users/model/users.model';
import { sign } from 'jsonwebtoken';
import * as process from 'process';
import { Request } from 'express';
import { JwtPayload } from './models/jwt.payload.model';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel('User')
    private readonly usersModel: Model<User>,
  ) {}

  public async createAccessToken(userId: string): Promise<string> {
    return sign({ userId }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRATION,
    });
  }

  public async validateUser(jwtPayload: JwtPayload): Promise<User> {
    return this.usersModel.findOne({ _id: jwtPayload.userId }).then((user) => {
      if (!user) {
        throw new UnauthorizedException('User not found');
      }
      return user;
    });
  }

  private static jwtExtractor(request: Request): string {
    const authHeader = request.headers.authorization;
    if (!authHeader) {
      throw new BadRequestException('Bad Request.');
    }
    const [, token] = authHeader.split(' ');
    return token;
  }

  public returnJwtExtractor(): (requst: Request) => string {
    return AuthService.jwtExtractor;
  }
}
